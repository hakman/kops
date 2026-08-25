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
	"path"
	"regexp"
	"strings"

	"k8s.io/kops/util/pkg/hashing"
)

func openOCIAsset(ctx context.Context, location *url.URL, expected *hashing.Hash) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	reader, err := openOCIAssetWithClient(ctx, newDownloadHTTPClient(), location, expected)
	if err != nil {
		cancel()
		return nil, err
	}
	return &cancelOnCloseReadCloser{ReadCloser: reader, cancel: cancel}, nil
}

func openOCIAssetWithClient(ctx context.Context, client *http.Client, location *url.URL, expected *hashing.Hash) (io.ReadCloser, error) {
	if expected == nil || expected.Algorithm != hashing.HashAlgorithmSHA256 {
		return nil, fmt.Errorf("OCI asset %q requires a SHA-256", location)
	}
	client = httpsOnlyRedirectClient(client)
	blobURL, repository, err := directOCIBlobURL(location, expected.Hex())
	if err != nil {
		return nil, err
	}

	response, err := getOCI(ctx, client, blobURL, "")
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusUnauthorized {
		challenges := response.Header.Values("WWW-Authenticate")
		response.Body.Close()
		token, err := requestAnonymousRegistryToken(ctx, client, challenges, repository)
		if err != nil {
			return nil, err
		}
		response, err = getOCI(ctx, client, blobURL, "Bearer "+token)
		if err != nil {
			return nil, err
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		return nil, fmt.Errorf("unexpected response from %q: HTTP %s", blobURL, response.Status)
	}
	return response.Body, nil
}

func directOCIBlobURL(location *url.URL, sha256 string) (string, string, error) {
	repository, err := ociRepository(location)
	if err != nil {
		return "", "", err
	}
	return "https://" + location.Host + "/v2/" + repository + "/blobs/sha256:" + sha256, repository, nil
}

func ociRepository(location *url.URL) (string, error) {
	if location.Scheme != "oci" || location.Host == "" || location.User != nil || location.RawQuery != "" || location.Fragment != "" {
		return "", fmt.Errorf("invalid OCI asset location %q", location)
	}
	reference := strings.Trim(location.Path, "/")
	separator := strings.LastIndex(reference, ":")
	if separator <= strings.LastIndex(reference, "/") || separator == len(reference)-1 {
		return "", fmt.Errorf("OCI asset location %q must include a tag", location)
	}
	return reference[:separator], nil
}

// OCIAssetFamily returns the final repository component, which identifies the asset family.
func OCIAssetFamily(location *url.URL) (string, error) {
	repository, err := ociRepository(location)
	if err != nil {
		return "", err
	}
	family := path.Base(repository)
	if family == "." || family == "/" {
		return "", fmt.Errorf("OCI asset location %q has no repository", location)
	}
	return family, nil
}

func getOCI(ctx context.Context, client *http.Client, location, authorization string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("downloading OCI blob %q: %w", location, err)
	}
	return response, nil
}

func requestAnonymousRegistryToken(ctx context.Context, client *http.Client, challenges []string, repository string) (string, error) {
	realm, service, err := bearerParameters(challenges)
	if err != nil {
		return "", err
	}
	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("invalid registry token realm %q: %w", realm, err)
	}
	if tokenURL.Scheme != "https" || tokenURL.Host == "" {
		return "", fmt.Errorf("registry token realm must use HTTPS: %q", realm)
	}
	query := tokenURL.Query()
	if service != "" {
		query.Set("service", service)
	}
	query.Set("scope", "repository:"+repository+":pull")
	tokenURL.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("requesting anonymous registry token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("registry token service returned HTTP %s", response.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decoding registry token: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", fmt.Errorf("registry token response did not contain a token")
}

func httpsOnlyRedirectClient(client *http.Client) *http.Client {
	clone := *client
	checkRedirect := clone.CheckRedirect
	clone.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" {
			return fmt.Errorf("OCI registry redirect must use HTTPS: %s", request.URL)
		}
		if checkRedirect != nil {
			return checkRedirect(request, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &clone
}

var (
	bearerChallengePattern = regexp.MustCompile(`(?i)(^|,)[[:space:]]*bearer[[:space:]]+`)
	bearerRealmPattern     = regexp.MustCompile(`(?i)(^|,)[[:space:]]*realm[[:space:]]*=[[:space:]]*"([^"]+)"`)
	bearerServicePattern   = regexp.MustCompile(`(?i)(^|,)[[:space:]]*service[[:space:]]*=[[:space:]]*"([^"]+)"`)
)

func bearerParameters(challenges []string) (string, string, error) {
	for _, header := range challenges {
		match := bearerChallengePattern.FindStringIndex(header)
		if match == nil {
			continue
		}
		parameters := header[match[1]:]
		realm := bearerRealmPattern.FindStringSubmatch(parameters)
		if realm == nil {
			continue
		}
		service := bearerServicePattern.FindStringSubmatch(parameters)
		if service != nil {
			return realm[2], service[2], nil
		}
		return realm[2], "", nil
	}
	return "", "", fmt.Errorf("registry authentication challenges contain no quoted Bearer realm: %q", challenges)
}
