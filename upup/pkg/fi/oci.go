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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"k8s.io/kops/util/pkg/hashing"
)

// ACRTokenUser is the well-known user for which an Azure Container Registry
// accepts its refresh token as the password.
const ACRTokenUser = "00000000-0000-0000-0000-000000000000"

// openOCIBlob opens a stream for an OCI registry blob addressed by digest.
// The URL has the form oci://<registry>/<repository>; the digest is the sha256
// hash of the asset. An Azure Container Registry is authenticated with the
// instance's managed identity; other registries must allow anonymous pulls.
func openOCIBlob(ctx context.Context, u *url.URL, hash *hashing.Hash) (io.ReadCloser, error) {
	if hash == nil {
		return nil, fmt.Errorf("OCI asset %q requires a known hash", u)
	}
	if hash.Algorithm != hashing.HashAlgorithmSHA256 {
		return nil, fmt.Errorf("OCI asset %q requires a sha256 hash, got %q", u, hash.Algorithm)
	}

	registry := u.Host
	repository := strings.Trim(u.Path, "/")
	if registry == "" || repository == "" {
		return nil, fmt.Errorf("cannot parse OCI asset URL %q; expected oci://<registry>/<repository>", u)
	}

	blobURL := fmt.Sprintf("https://%s/v2/%s/blobs/sha256:%s", registry, repository, hash.Hex())
	httpClient := newDownloadHTTPClient()

	token := ""
	if strings.HasSuffix(registry, ".azurecr.io") {
		acrToken, err := acrPullToken(ctx, registry, repository)
		if err != nil {
			return nil, fmt.Errorf("getting pull token for registry %q: %w", registry, err)
		}
		token = acrToken
	}

	response, err := getOCIBlob(ctx, httpClient, blobURL, token)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusUnauthorized && token == "" {
		// Anonymous pulls may still need a token, obtained anonymously from the
		// endpoint advertised in the unauthorized response's challenge.
		challenge := response.Header.Get("WWW-Authenticate")
		response.Body.Close()
		token, err = anonymousPullToken(ctx, challenge, repository)
		if err != nil {
			return nil, fmt.Errorf("getting anonymous pull token for registry %q: %w", registry, err)
		}
		response, err = getOCIBlob(ctx, httpClient, blobURL, token)
		if err != nil {
			return nil, err
		}
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		response.Body.Close()
		return nil, fmt.Errorf("unexpected response from %q: HTTP %s", blobURL, response.Status)
	}
	return response.Body, nil
}

func getOCIBlob(ctx context.Context, httpClient *http.Client, blobURL, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error doing HTTP fetch of %q: %w", blobURL, err)
	}
	return response, nil
}

// anonymousPullToken obtains a pull token for an anonymous client from the token
// endpoint advertised in a registry's WWW-Authenticate challenge.
func anonymousPullToken(ctx context.Context, challenge, repository string) (string, error) {
	realm, service, err := parseBearerChallenge(challenge)
	if err != nil {
		return "", err
	}

	tokenURL := realm + "?service=" + url.QueryEscape(service) + "&scope=" + url.QueryEscape("repository:"+repository+":pull")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}

	response, err := newDownloadHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("error querying %q: %w", tokenURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("unexpected response from %q: HTTP %s", tokenURL, response.Status)
	}

	// Registries return the token as "token" (Docker registry auth) or "access_token" (OAuth2).
	return tokenFromJSON(response.Body, "token", "access_token")
}

// parseBearerChallenge extracts the realm and service from a Bearer WWW-Authenticate
// challenge, such as `Bearer realm="https://auth.example.com/token",service="example.com"`.
func parseBearerChallenge(challenge string) (string, string, error) {
	params, ok := strings.CutPrefix(challenge, "Bearer ")
	if !ok {
		return "", "", fmt.Errorf("unsupported WWW-Authenticate challenge %q", challenge)
	}

	var realm, service string
	for _, param := range strings.Split(params, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found {
			continue
		}
		switch key {
		case "realm":
			realm = strings.Trim(value, `"`)
		case "service":
			service = strings.Trim(value, `"`)
		}
	}
	if realm == "" {
		return "", "", fmt.Errorf("WWW-Authenticate challenge %q does not contain a realm", challenge)
	}
	return realm, service, nil
}

// acrRefreshTokens caches the registry refresh token per registry: every asset
// download needs one, and the token far outlives a node boot.
var (
	acrRefreshTokensMu sync.Mutex
	acrRefreshTokens   = map[string]string{}
)

// acrRefreshToken exchanges the instance's managed-identity token for an Azure
// Container Registry refresh token, caching it per registry.
func acrRefreshToken(ctx context.Context, registry string) (string, error) {
	acrRefreshTokensMu.Lock()
	defer acrRefreshTokensMu.Unlock()
	if refreshToken, ok := acrRefreshTokens[registry]; ok {
		return refreshToken, nil
	}

	aadToken, err := azureInstanceIdentityToken(ctx)
	if err != nil {
		return "", err
	}

	refreshToken, err := ACRExchangeToken(ctx, registry, aadToken)
	if err != nil {
		return "", fmt.Errorf("exchanging identity token for a registry refresh token: %w", err)
	}

	acrRefreshTokens[registry] = refreshToken
	return refreshToken, nil
}

// ACRExchangeToken exchanges an Entra ID access token for an Azure Container
// Registry refresh token.
func ACRExchangeToken(ctx context.Context, registry, aadToken string) (string, error) {
	return acrOAuthRequest(ctx,
		fmt.Sprintf("https://%s/oauth2/exchange", registry),
		url.Values{
			"grant_type":   []string{"access_token"},
			"service":      []string{registry},
			"access_token": []string{aadToken},
		},
		"refresh_token")
}

// acrPullToken exchanges the instance's managed-identity token for an Azure
// Container Registry access token scoped to pulling from the given repository.
func acrPullToken(ctx context.Context, registry, repository string) (string, error) {
	refreshToken, err := acrRefreshToken(ctx, registry)
	if err != nil {
		return "", err
	}

	accessToken, err := acrOAuthRequest(ctx,
		fmt.Sprintf("https://%s/oauth2/token", registry),
		url.Values{
			"grant_type":    []string{"refresh_token"},
			"service":       []string{registry},
			"scope":         []string{fmt.Sprintf("repository:%s:pull", repository)},
			"refresh_token": []string{refreshToken},
		},
		"access_token")
	if err != nil {
		return "", fmt.Errorf("getting a registry access token: %w", err)
	}

	return accessToken, nil
}

// imdsHTTPClient is used for instance metadata service queries. The explicit
// Transport{Proxy: nil} bypasses any system proxy since IMDS lives at the
// link-local 169.254.169.254 address and must not be routed through one.
var imdsHTTPClient = &http.Client{
	Transport: &http.Transport{Proxy: nil},
	Timeout:   10 * time.Second,
}

// azureInstanceIdentityToken returns a managed-identity token from the Azure
// instance metadata service.
func azureInstanceIdentityToken(ctx context.Context) (string, error) {
	imdsURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + url.QueryEscape("https://management.azure.com/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsURL, nil)
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	response, err := imdsHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error querying the instance metadata service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("unexpected response from the instance metadata service: HTTP %s", response.Status)
	}

	return tokenFromJSON(response.Body, "access_token")
}

func acrOAuthRequest(ctx context.Context, endpoint string, values url.Values, tokenField string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error posting to %q: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("unexpected response from %q: HTTP %s", endpoint, response.Status)
	}

	return tokenFromJSON(response.Body, tokenField)
}

func tokenFromJSON(r io.Reader, fields ...string) (string, error) {
	var body map[string]any
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		return "", fmt.Errorf("cannot decode response: %w", err)
	}
	for _, field := range fields {
		if token, _ := body[field].(string); token != "" {
			return token, nil
		}
	}
	return "", fmt.Errorf("response did not contain %s", strings.Join(fields, " or "))
}
