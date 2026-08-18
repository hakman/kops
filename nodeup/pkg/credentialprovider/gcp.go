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

// Adapted from k8s.io/cloud-provider-gcp cmd/auth-provider-gcp and
// pkg/gcpcredential (v35.0.0), trimmed to the default "gcr" auth flow that
// the kOps-generated credential provider config uses: the access token of
// the instance's default service account, read from the metadata server, is
// returned as the registry password.

package credentialprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const (
	metadataURL   = "http://metadata.google.internal./computeMetadata/v1/"
	metadataToken = metadataURL + "instance/service-accounts/default/token"
	metadataEmail = metadataURL + "instance/service-accounts/default/email"

	metadataHTTPClientTimeout = time.Second * 10
)

// For these urls, the parts of the host name can be glob, for example '*.gcr.io" will match
// "foo.gcr.io" and "bar.gcr.io".
var containerRegistryUrls = []string{"container.cloud.google.com", "gcr.io", "*.gcr.io", "*.pkg.dev"}

// GCPProvider fetches credentials for GCR and Artifact Registry from the
// GCE metadata server.
type GCPProvider struct {
	client *http.Client

	// tokenURL and emailURL override the metadata server endpoints for testing.
	tokenURL string
	emailURL string
}

// NewGCPProvider returns a GCPProvider that reads the default service
// account's access token from the GCE metadata server.
func NewGCPProvider() *GCPProvider {
	return &GCPProvider{
		client:   &http.Client{Timeout: metadataHTTPClientTimeout},
		tokenURL: metadataToken,
		emailURL: metadataEmail,
	}
}

// tokenBlob is used to decode the JSON blob containing an access token
// that is returned by GCE metadata.
type tokenBlob struct {
	AccessToken string `json:"access_token"`
}

// GetCredentials implements Provider.
func (g *GCPProvider) GetCredentials(ctx context.Context, image string) (*v1.CredentialProviderResponse, error) {
	tokenJSONBlob, err := g.readURL(ctx, g.tokenURL)
	if err != nil {
		return nil, fmt.Errorf("while reading access token endpoint: %w", err)
	}

	// The email is fetched to match upstream behavior (it validates that the
	// default service account exists) but is not part of the response.
	if _, err := g.readURL(ctx, g.emailURL); err != nil {
		return nil, fmt.Errorf("while reading email endpoint: %w", err)
	}

	var parsedBlob tokenBlob
	if err := json.Unmarshal(tokenJSONBlob, &parsedBlob); err != nil {
		// The token blob is intentionally not included so as to not leak
		// credentials into the logs.
		return nil, fmt.Errorf("while parsing token json blob: %w", err)
	}

	entry := v1.AuthConfig{
		Username: "_token",
		Password: parsedBlob.AccessToken,
	}

	auth := map[string]v1.AuthConfig{}

	// Directly give the credential to the registry of the image.
	if registry, _, found := strings.Cut(image, "/"); found {
		auth[registry] = entry
	}

	// Add our entry for each of the supported container registry URLs
	for _, k := range containerRegistryUrls {
		auth[k] = entry
	}

	return &v1.CredentialProviderResponse{
		CacheKeyType: v1.ImagePluginCacheKeyType,
		// A cache duration of 0 means the kubelet does not cache the
		// credentials in-memory, matching the upstream default.
		CacheDuration: &metav1.Duration{Duration: 0},
		Auth:          auth,
	}, nil
}

func (g *GCPProvider) readURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status code: %d while fetching url %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}
