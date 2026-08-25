/*
Copyright 2026 The Kubernetes Authors.

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

package fi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"k8s.io/kops/util/pkg/hashing"
)

func TestOpenOCIAssetUsesDigestAndAnonymousToken(t *testing.T) {
	content := []byte("asset bytes")
	hash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	blobPath := "/v2/prefix/containerd/blobs/sha256:" + hash.Hex()
	var requests []string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/token":
			if got := r.URL.Query().Get("scope"); got != "repository:prefix/containerd:pull" {
				t.Errorf("scope = %q", got)
			}
			fmt.Fprint(w, `{"access_token":"pull-token"}`)
		case blobPath:
			if r.Header.Get("Authorization") == "Bearer pull-token" {
				w.Write(content)
				return
			}
			w.Header().Add("WWW-Authenticate", `Basic realm="legacy"`)
			w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token?audience=assets,public", service="registry"`, server.URL))
			w.WriteHeader(http.StatusUnauthorized)
		default:
			t.Errorf("unexpected request %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	location, err := url.Parse("oci://" + strings.TrimPrefix(server.URL, "https://") + "/prefix/containerd:v2.2.4-amd64")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := openOCIAssetWithClient(context.Background(), server.Client(), location, hash)
	if err != nil {
		t.Fatalf("openOCIAssetWithClient() error = %v", err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("downloaded %q, want %q", got, content)
	}
	want := []string{blobPath, "/token", blobPath}
	if fmt.Sprint(requests) != fmt.Sprint(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
}

func TestOpenOCIAssetRejectsHTTPRedirect(t *testing.T) {
	content := []byte("asset bytes")
	hash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	reachedHTTP := false
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedHTTP = true
		w.Write(content)
	}))
	defer httpServer.Close()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpServer.URL+"/blob", http.StatusTemporaryRedirect)
	}))
	defer tlsServer.Close()

	location, err := url.Parse("oci://" + strings.TrimPrefix(tlsServer.URL, "https://") + "/prefix/containerd:v2.2.4-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openOCIAssetWithClient(context.Background(), tlsServer.Client(), location, hash); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("openOCIAssetWithClient() error = %v, want HTTPS redirect error", err)
	}
	if reachedHTTP {
		t.Fatal("OCI download followed an HTTP redirect")
	}
}

func TestRequestAnonymousRegistryTokenRejectsHTTPRealm(t *testing.T) {
	challenges := []string{`Bearer realm="http://auth.example.com/token",service="registry"`}
	if _, err := requestAnonymousRegistryToken(context.Background(), http.DefaultClient, challenges, "prefix/containerd"); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("requestAnonymousRegistryToken() error = %v, want HTTPS realm error", err)
	}
}

func TestBearerParameters(t *testing.T) {
	tests := []struct {
		name        string
		challenges  []string
		wantRealm   string
		wantService string
	}{
		{
			name:        "separate headers",
			challenges:  []string{`Basic realm="legacy"`, `Bearer realm="https://auth.example.com/token",service="registry"`},
			wantRealm:   "https://auth.example.com/token",
			wantService: "registry",
		},
		{
			name:        "combined challenges and quoted comma",
			challenges:  []string{`Basic realm="legacy", Bearer realm="https://auth.example.com/token?audience=assets,public", service= "registry"`},
			wantRealm:   "https://auth.example.com/token?audience=assets,public",
			wantService: "registry",
		},
		{
			name:        "mixed case and whitespace",
			challenges:  []string{`bEaReR ReAlM = "https://auth.example.com/token", SeRvIcE= "registry"`},
			wantRealm:   "https://auth.example.com/token",
			wantService: "registry",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			realm, service, err := bearerParameters(test.challenges)
			if err != nil {
				t.Fatal(err)
			}
			if realm != test.wantRealm || service != test.wantService {
				t.Fatalf("bearerParameters() = %q, %q, want %q, %q", realm, service, test.wantRealm, test.wantService)
			}
		})
	}

	for _, challenges := range [][]string{
		{`Basic realm="legacy"`},
		{`Bearer realm="https://auth.example.com/token`},
		{`Bearer realm=https://auth.example.com/token`},
	} {
		if _, _, err := bearerParameters(challenges); err == nil {
			t.Fatalf("bearerParameters(%q) returned no error", challenges)
		}
	}
}

func TestDirectOCIBlobURLRejectsUntaggedLocation(t *testing.T) {
	location, err := url.Parse("oci://registry.example.com/prefix/containerd")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := directOCIBlobURL(location, strings.Repeat("0", 64)); err == nil {
		t.Fatal("directOCIBlobURL() accepted an untagged location")
	}
}

func TestOCIAssetFamily(t *testing.T) {
	location, err := url.Parse("oci://registry.example.com/optional-prefix/ecr-credential-provider:v1.31.7-arm64")
	if err != nil {
		t.Fatal(err)
	}
	family, err := OCIAssetFamily(location)
	if err != nil {
		t.Fatal(err)
	}
	if family != "ecr-credential-provider" {
		t.Fatalf("OCIAssetFamily() = %q", family)
	}
}
