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
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"k8s.io/kops/pkg/assets"
	"k8s.io/kops/pkg/assets/assetcopy"
	"k8s.io/kops/util/pkg/hashing"
	"k8s.io/kops/util/pkg/vfs"
)

func TestOCIAssetRegistryProtocol(t *testing.T) {
	content := []byte("exact kubelet bytes")
	hash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "kubelet")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}

	registry := newMemoryOCIRegistry()
	server := httptest.NewTLSServer(registry)
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	registryHost := net.JoinHostPort("registry.example.com", port)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	originalTransport := remote.DefaultTransport
	remote.DefaultTransport = transport
	t.Cleanup(func() {
		remote.DefaultTransport = originalTransport
		transport.CloseIdleConnections()
	})

	location, err := url.Parse("oci://" + registryHost + "/optional-prefix/kubelet:v1.32.0-amd64")
	if err != nil {
		t.Fatal(err)
	}
	fileAsset := &assets.FileAsset{
		CanonicalURL: &url.URL{Path: source},
		DownloadURL:  location,
		SHAValue:     hash,
	}
	if err := assetcopy.Copy(nil, []*assets.FileAsset{fileAsset}, vfs.Context, nil); err != nil {
		t.Fatalf("Copy() error = %v", err)
	}
	registry.resetRequests()
	if err := assetcopy.Copy(nil, []*assets.FileAsset{fileAsset}, vfs.Context, nil); err != nil {
		t.Fatalf("idempotent Copy() error = %v", err)
	}
	for _, request := range registry.requests() {
		if strings.HasPrefix(request, "POST ") || strings.HasPrefix(request, "PATCH ") || strings.HasPrefix(request, "PUT ") {
			t.Errorf("idempotent staging made a mutating request: %s", request)
		}
	}

	if !registry.hasManifest("/v2/optional-prefix/kubelet/manifests/v1.32.0-amd64") {
		t.Error("semantic manifest was not staged")
	}

	registry.resetRequests()
	blobPath := "/v2/optional-prefix/kubelet/blobs/sha256:" + hash.Hex()
	reader, err := openOCIAssetWithClient(context.Background(), &http.Client{Transport: transport}, location, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("direct blob response = %q, want %q", got, content)
	}
	if got := registry.requests(); fmt.Sprint(got) != fmt.Sprint([]string{"GET " + blobPath}) {
		t.Fatalf("node pull requests = %v, want only the direct blob endpoint", got)
	}
}

type memoryOCIRegistry struct {
	mu         sync.Mutex
	nextID     int
	blobs      map[string][]byte
	uploads    map[string][]byte
	manifests  map[string]storedManifest
	requestLog []string
}

type storedManifest struct {
	body      []byte
	mediaType string
}

func newMemoryOCIRegistry() *memoryOCIRegistry {
	return &memoryOCIRegistry{
		blobs:     make(map[string][]byte),
		uploads:   make(map[string][]byte),
		manifests: make(map[string]storedManifest),
	}
}

func (r *memoryOCIRegistry) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	r.requestLog = append(r.requestLog, request.Method+" "+request.URL.Path)
	r.mu.Unlock()

	switch {
	case request.URL.Path == "/v2/" || request.URL.Path == "/v2":
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	case strings.Contains(request.URL.Path, "/blobs/uploads/"):
		r.serveUpload(w, request)
	case strings.Contains(request.URL.Path, "/blobs/sha256:"):
		r.serveBlob(w, request)
	case strings.Contains(request.URL.Path, "/manifests/"):
		r.serveManifest(w, request)
	default:
		http.NotFound(w, request)
	}
}

func (r *memoryOCIRegistry) serveUpload(w http.ResponseWriter, request *http.Request) {
	const marker = "/blobs/uploads/"
	i := strings.Index(request.URL.Path, marker)
	uploadID := request.URL.Path[i+len(marker):]

	switch request.Method {
	case http.MethodPost:
		if uploadID != "" {
			http.NotFound(w, request)
			return
		}
		r.mu.Lock()
		r.nextID++
		location := request.URL.Path + fmt.Sprint(r.nextID)
		r.uploads[location] = nil
		r.mu.Unlock()
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPatch:
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.uploads[request.URL.Path] = body
		r.mu.Unlock()
		w.Header().Set("Location", request.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		r.commitUpload(w, request, request.URL.Path[:i])
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (r *memoryOCIRegistry) commitUpload(w http.ResponseWriter, request *http.Request, repositoryPath string) {
	digest := request.URL.Query().Get("digest")
	r.mu.Lock()
	body, ok := r.uploads[request.URL.Path]
	r.mu.Unlock()
	sum := sha256.Sum256(body)
	if !ok || digest != fmt.Sprintf("sha256:%x", sum) {
		http.Error(w, "invalid upload digest", http.StatusBadRequest)
		return
	}
	blobPath := repositoryPath + "/blobs/" + digest
	r.mu.Lock()
	r.blobs[blobPath] = body
	delete(r.uploads, request.URL.Path)
	r.mu.Unlock()
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", blobPath)
	w.WriteHeader(http.StatusCreated)
}

func (r *memoryOCIRegistry) serveBlob(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	body, ok := r.blobs[request.URL.Path]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, request)
		return
	}
	w.Header().Set("Docker-Content-Digest", request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:])
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (r *memoryOCIRegistry) serveManifest(w http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPut:
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.manifests[request.URL.Path] = storedManifest{body: body, mediaType: request.Header.Get("Content-Type")}
		r.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet, http.MethodHead:
		r.mu.Lock()
		manifest, ok := r.manifests[request.URL.Path]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", manifest.mediaType)
		w.Header().Set("Content-Length", fmt.Sprint(len(manifest.body)))
		digest := sha256.Sum256(manifest.body)
		w.Header().Set("Docker-Content-Digest", fmt.Sprintf("sha256:%x", digest))
		w.WriteHeader(http.StatusOK)
		if request.Method != http.MethodHead {
			_, _ = w.Write(manifest.body)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (r *memoryOCIRegistry) hasManifest(path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.manifests[path]
	return ok
}

func (r *memoryOCIRegistry) resetRequests() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requestLog = nil
}

func (r *memoryOCIRegistry) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requestLog...)
}
