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

package credentialprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

func newFakeMetadataServer(t *testing.T, tokenStatus int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor header", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/token":
			if tokenStatus != http.StatusOK {
				http.Error(w, "error", tokenStatus)
				return
			}
			w.Write([]byte(`{"access_token":"ya29.secret","expires_in":3599,"token_type":"Bearer"}`))
		case "/email":
			w.Write([]byte("default@project.iam.gserviceaccount.com"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func Test_GCPProvider_GetCredentials(t *testing.T) {
	server := newFakeMetadataServer(t, http.StatusOK)

	p := &GCPProvider{
		client:   server.Client(),
		tokenURL: server.URL + "/token",
		emailURL: server.URL + "/email",
	}

	creds, err := p.GetCredentials(context.TODO(), "us-central1-docker.pkg.dev/project/repo/image:tag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if creds.CacheKeyType != v1.ImagePluginCacheKeyType {
		t.Errorf("unexpected CacheKeyType: %s", creds.CacheKeyType)
	}
	if creds.CacheDuration == nil || creds.CacheDuration.Duration != 0 {
		t.Errorf("unexpected CacheDuration: %v", creds.CacheDuration)
	}

	expectedRegistries := []string{
		"us-central1-docker.pkg.dev",
		"container.cloud.google.com",
		"gcr.io",
		"*.gcr.io",
		"*.pkg.dev",
	}
	for _, registry := range expectedRegistries {
		auth, ok := creds.Auth[registry]
		if !ok {
			t.Errorf("missing auth entry for %q", registry)
			continue
		}
		if auth.Username != "_token" {
			t.Errorf("unexpected username for %q: %s", registry, auth.Username)
		}
		if auth.Password != "ya29.secret" {
			t.Errorf("unexpected password for %q: %s", registry, auth.Password)
		}
	}
	if len(creds.Auth) != len(expectedRegistries) {
		t.Errorf("unexpected auth entries: %v", creds.Auth)
	}
}

func Test_GCPProvider_GetCredentials_TokenError(t *testing.T) {
	server := newFakeMetadataServer(t, http.StatusNotFound)

	p := &GCPProvider{
		client:   server.Client(),
		tokenURL: server.URL + "/token",
		emailURL: server.URL + "/email",
	}

	if _, err := p.GetCredentials(context.TODO(), "gcr.io/project/image:tag"); err == nil {
		t.Fatal("expected error, got none")
	}
}
