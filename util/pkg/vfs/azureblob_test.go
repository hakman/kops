/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vfs

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

func TestIsValidAzureStorageAccountName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{name: "abc", valid: true},
		{name: "account123", valid: true},
		{name: "abcdefghijklmnopqrstuvwx", valid: true},
		{name: "ab"},
		{name: "abcdefghijklmnopqrstuvwxy"},
		{name: "UPPERCASE"},
		{name: "bad-account"},
		{name: "bad;account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidAzureStorageAccountName(tc.name); got != tc.valid {
				t.Errorf("IsValidAzureStorageAccountName(%q) = %v, expected %v", tc.name, got, tc.valid)
			}
		})
	}
}

func TestAzureBlobPathBase(t *testing.T) {
	testCases := []struct {
		container string
		key       string
		base      string
	}{
		{
			container: "c",
			key:       "foo/bar",
			base:      "bar",
		},
		{
			container: "c/",
			key:       "/foo/bar",
			base:      "bar",
		},
		{
			container: "c",
			key:       "/foo/bar/",
			base:      "bar",
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Test case %d", i), func(t *testing.T) {
			p := NewAzureBlobPath(nil, "a", tc.container, tc.key)
			if a := p.Base(); a != tc.base {
				t.Errorf("expected %s, but got %s", tc.base, a)
			}
		})
	}
}

func TestAzureBlobPathPath(t *testing.T) {
	testCases := []struct {
		account   string
		container string
		key       string
		path      string
	}{
		{
			account:   "a",
			container: "c",
			key:       "foo/bar",
			path:      "azureblob://a/c/foo/bar",
		},
		{
			account:   "a",
			container: "c/",
			key:       "/foo/bar",
			path:      "azureblob://a/c/foo/bar",
		},
		{
			account:   "a",
			container: "c",
			key:       "/foo/bar/",
			path:      "azureblob://a/c/foo/bar/",
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Test case %d", i), func(t *testing.T) {
			p := NewAzureBlobPath(nil, tc.account, tc.container, tc.key)
			if a := p.Path(); a != tc.path {
				t.Errorf("expected %s, but got %s", tc.path, a)
			}
		})
	}
	p := NewAzureBlobPath(nil, "account", "container", "foo/bar")
	if a, e := p.Path(), "azureblob://account/container/foo/bar"; a != e {
		t.Errorf("expected %s, but got %s", e, a)
	}
}

func TestAzureBlobPathJoin(t *testing.T) {
	p := NewAzureBlobPath(nil, "a", "c", "foo/bar")
	joined := p.Join("p1", "p2")
	if a, e := joined.Path(), "azureblob://a/c/foo/bar/p1/p2"; a != e {
		t.Errorf("expected %s, but got %s", e, a)
	}
}

func TestBuildAzureBlobPath(t *testing.T) {
	testCases := []struct {
		input     string
		account   string
		container string
		key       string
		wantErr   bool
	}{
		{
			input:     "azureblob://account/container/key/path",
			account:   "account",
			container: "container",
			key:       "key/path",
		},
		{
			input:     "azureblob://account/container",
			account:   "account",
			container: "container",
			key:       "",
		},
		{
			// Old format without account is rejected.
			input:   "azureblob://container",
			wantErr: true,
		},
		{
			// Account but no container.
			input:   "azureblob://account/",
			wantErr: true,
		},
		{
			input:   "azureblob://bad;account/container/key",
			wantErr: true,
		},
	}
	c := &VFSContext{}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			p, err := c.buildAzureBlobPath(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %+v", tc.input, p)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if p.account != tc.account {
				t.Errorf("account: expected %q, got %q", tc.account, p.account)
			}
			if p.container != tc.container {
				t.Errorf("container: expected %q, got %q", tc.container, p.container)
			}
			if p.key != tc.key {
				t.Errorf("key: expected %q, got %q", tc.key, p.key)
			}
		})
	}
}

type firstWriteBuffer struct {
	buffer     bytes.Buffer
	once       sync.Once
	firstWrite chan struct{}
}

func (w *firstWriteBuffer) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.firstWrite) })
	return w.buffer.Write(p)
}

func TestAzureBlobPathWriteToStreams(t *testing.T) {
	firstChunk := []byte("first chunk")
	secondChunk := []byte("second chunk")
	firstChunkSent := make(chan struct{})
	releaseResponse := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(firstChunk)
		w.(http.Flusher).Flush()
		close(firstChunkSent)
		<-releaseResponse
		_, _ = w.Write(secondChunk)
	}))
	defer server.Close()
	released := false
	defer func() {
		if !released {
			close(releaseResponse)
		}
	}()

	client, err := azblob.NewClientWithNoCredential(server.URL, nil)
	if err != nil {
		t.Fatalf("creating Azure Blob client: %v", err)
	}
	vfsContext := NewVFSContext()
	vfsContext.azureClients = map[string]*azblob.Client{"account": client}
	p := NewAzureBlobPath(vfsContext, "account", "container", "key")
	w := &firstWriteBuffer{firstWrite: make(chan struct{})}

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := p.WriteToWithContext(context.Background(), w)
		done <- result{n: n, err: err}
	}()

	<-firstChunkSent
	select {
	case <-w.firstWrite:
	case <-time.After(5 * time.Second):
		t.Fatal("destination did not receive data before the blob response completed")
	}

	close(releaseResponse)
	released = true
	r := <-done
	if r.err != nil {
		t.Fatalf("streaming Azure Blob content: %v", r.err)
	}
	expected := append(firstChunk, secondChunk...)
	if r.n != int64(len(expected)) {
		t.Errorf("wrote %d bytes, expected %d", r.n, len(expected))
	}
	if !bytes.Equal(w.buffer.Bytes(), expected) {
		t.Errorf("wrote %q, expected %q", w.buffer.Bytes(), expected)
	}
}
