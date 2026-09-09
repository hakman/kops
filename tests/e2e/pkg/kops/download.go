/*
Copyright 2021 The Kubernetes Authors.

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

package kops

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"

	"k8s.io/kops/tests/e2e/pkg/util"
)

// DownloadKops will download the kops binary from the version marker URL
// Returning the URL to use for KOPS_BASE_URL
// Example markerURL: https://storage.googleapis.com/k8s-staging-kops/kops/releases/latest.txt
func DownloadKops(markerURL, downloadPath, kopsVersion string) (string, error) {
	var b bytes.Buffer
	var kopsBaseURL string
	if markerURL == "" && kopsVersion != "" {
		kopsBaseURL = fmt.Sprintf("https://artifacts.k8s.io/binaries/kops/%s", kopsVersion)
	}
	if markerURL != "" && kopsVersion == "" {
		if err := util.HTTPGETWithHeaders(markerURL, nil, &b); err != nil {
			return "", err
		}
		baseURL, err := kopsBaseURLFromMarker(markerURL, b.String())
		if err != nil {
			return "", err
		}
		kopsBaseURL = baseURL
	}

	kopsFile, err := os.Create(downloadPath)
	if err != nil {
		return "", err
	}

	kopsURL := fmt.Sprintf("%v/%v/%v/kops", kopsBaseURL, runtime.GOOS, runtime.GOARCH)
	if err := util.HTTPGETWithHeaders(kopsURL, nil, kopsFile); err != nil {
		return "", err
	}
	if err := kopsFile.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(kopsFile.Name(), 0o755); err != nil {
		return "", err
	}
	return kopsBaseURL, nil
}

// kopsBaseURLFromMarker returns the KOPS_BASE_URL for a version marker.
// Markers hold only the version, and the artifacts live next to the marker, e.g.
// https://storage.googleapis.com/k8s-staging-kops/kops/releases/latest.txt -> 1.37.0-beta.2+abc123
// resolves to https://storage.googleapis.com/k8s-staging-kops/kops/releases/1.37.0-beta.2+abc123
// Legacy markers hold the full KOPS_BASE_URL and are returned as-is.
func kopsBaseURLFromMarker(markerURL string, contents string) (string, error) {
	contents = strings.TrimSpace(contents)
	if strings.Contains(contents, "://") {
		return contents, nil
	}
	if contents == "" || strings.ContainsAny(contents, "/ \t\n") {
		return "", fmt.Errorf("version marker %s does not contain a version: %q", markerURL, contents)
	}
	u, err := url.Parse(markerURL)
	if err != nil {
		return "", fmt.Errorf("parsing version marker URL %q: %w", markerURL, err)
	}
	u.Path = path.Join(path.Dir(u.Path), contents)
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
