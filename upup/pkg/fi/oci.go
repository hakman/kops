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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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

	auth := ""
	switch {
	case strings.HasSuffix(registry, ".azurecr.io"):
		// Azure Container Registry: authenticate with the instance's managed identity.
		token, err := acrPullToken(ctx, registry, repository)
		if err != nil {
			return nil, fmt.Errorf("getting pull token for registry %q: %w", registry, err)
		}
		auth = "Bearer " + token
	case strings.HasSuffix(registry, ".pkg.dev"):
		// Artifact Registry: authenticate with an access token for the
		// instance's service account, accepted directly as a bearer token.
		token, err := gceInstanceAccessToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting pull token for registry %q: %w", registry, err)
		}
		auth = "Bearer " + token
	case isECRRegistry(registry):
		// Amazon ECR: authenticate with an authorization token obtained with
		// the instance role credentials, used as HTTP basic auth.
		header, err := ecrAuthorizationHeader(ctx, registry)
		if err != nil {
			return nil, fmt.Errorf("getting pull token for registry %q: %w", registry, err)
		}
		auth = header
	}

	response, err := getOCIBlob(ctx, httpClient, blobURL, auth)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusUnauthorized && auth == "" {
		// Anonymous pulls may still need a token, obtained anonymously from the
		// endpoint advertised in the unauthorized response's challenge.
		challenge := response.Header.Get("WWW-Authenticate")
		response.Body.Close()
		token, err := anonymousPullToken(ctx, challenge, repository)
		if err != nil {
			return nil, fmt.Errorf("getting anonymous pull token for registry %q: %w", registry, err)
		}
		response, err = getOCIBlob(ctx, httpClient, blobURL, "Bearer "+token)
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

func getOCIBlob(ctx context.Context, httpClient *http.Client, blobURL, auth string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
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

// gceInstanceAccessToken returns an access token for the instance's service
// account from the GCE metadata service.
func gceInstanceAccessToken(ctx context.Context) (string, error) {
	metadataURL := "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

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

// isECRRegistry reports whether the registry is an Amazon ECR private registry
// (<account>.dkr.ecr.<region>.amazonaws.com).
func isECRRegistry(registry string) bool {
	return strings.Contains(registry, ".dkr.ecr.") && strings.HasSuffix(registry, ".amazonaws.com")
}

// ecrAuthHeaders caches the Authorization header per registry: every asset
// download needs one, and the authorization token is valid for 12 hours.
var (
	ecrAuthMu      sync.Mutex
	ecrAuthHeaders = map[string]string{}
)

// ecrAuthorizationHeader returns the Authorization header for an Amazon ECR
// registry: an authorization token obtained with the instance role credentials,
// which the registry accepts as HTTP basic auth.
func ecrAuthorizationHeader(ctx context.Context, registry string) (string, error) {
	ecrAuthMu.Lock()
	defer ecrAuthMu.Unlock()
	if header, ok := ecrAuthHeaders[registry]; ok {
		return header, nil
	}

	region, err := ecrRegistryRegion(registry)
	if err != nil {
		return "", err
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return "", fmt.Errorf("loading AWS config: %w", err)
	}
	credentials, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("retrieving AWS credentials: %w", err)
	}

	// Call GetAuthorizationToken directly, without linking the ECR service client.
	body := "{}"
	endpoint := fmt.Sprintf("https://api.ecr.%s.amazonaws.com/", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("cannot create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken")
	payloadHash := sha256.Sum256([]byte(body))
	if err := awsv4.NewSigner().SignHTTP(ctx, credentials, req, hex.EncodeToString(payloadHash[:]), "ecr", region, time.Now()); err != nil {
		return "", fmt.Errorf("signing the request: %w", err)
	}

	response, err := newDownloadHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("error posting to %q: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("unexpected response from %q: HTTP %s", endpoint, response.Status)
	}

	var result struct {
		AuthorizationData []struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"authorizationData"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("cannot decode response: %w", err)
	}
	if len(result.AuthorizationData) == 0 || result.AuthorizationData[0].AuthorizationToken == "" {
		return "", fmt.Errorf("response from %q did not contain an authorization token", endpoint)
	}

	header := "Basic " + result.AuthorizationData[0].AuthorizationToken
	ecrAuthHeaders[registry] = header
	return header, nil
}

// ecrRegistryRegion extracts the region from an Amazon ECR registry host
// (<account>.dkr.ecr.<region>.amazonaws.com).
func ecrRegistryRegion(registry string) (string, error) {
	_, after, found := strings.Cut(registry, ".dkr.ecr.")
	region, _, _ := strings.Cut(after, ".")
	if !found || region == "" {
		return "", fmt.Errorf("cannot extract the region from ECR registry %q", registry)
	}
	return region, nil
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
