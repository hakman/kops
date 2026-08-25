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

package wellknownassets

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"k8s.io/kops"
	apiskops "k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/assets"
	"k8s.io/kops/util/pkg/architectures"
	"k8s.io/kops/util/pkg/hashing"
	"k8s.io/kops/util/pkg/vfs"
)

func TestBaseURL_OverridesVersionFromKopsBaseURL(t *testing.T) {
	origVersion := kops.Version
	t.Cleanup(func() {
		kops.Version = origVersion
		kopsBaseURL = nil
	})

	tests := []struct {
		name            string
		kopsBaseURL     string
		expectedVersion string
	}{
		{
			name:            "postsubmit URL",
			kopsBaseURL:     "https://storage.googleapis.com/k8s-staging-kops/kops/releases/1.35.0-beta.2+v1.37.0-alpha.1-384-gf369c3ab16",
			expectedVersion: "1.35.0-beta.2+v1.37.0-alpha.1-384-gf369c3ab16",
		},
		{
			name:            "postsubmit URL with trailing slash",
			kopsBaseURL:     "https://storage.googleapis.com/k8s-staging-kops/kops/releases/1.35.0-beta.2+v1.37.0-alpha.1-384-gf369c3ab16/",
			expectedVersion: "1.35.0-beta.2+v1.37.0-alpha.1-384-gf369c3ab16",
		},
		{
			name:            "CI URL",
			kopsBaseURL:     "https://storage.googleapis.com/k8s-staging-kops/kops/ci/1.35.0-beta.2+abc123",
			expectedVersion: "1.35.0-beta.2+abc123",
		},
		{
			name:            "CI URL with trailing slash",
			kopsBaseURL:     "https://storage.googleapis.com/k8s-staging-kops/kops/ci/1.35.0-beta.2+abc123/",
			expectedVersion: "1.35.0-beta.2+abc123",
		},
		{
			name:            "release URL",
			kopsBaseURL:     "https://artifacts.k8s.io/binaries/kops/1.35.0",
			expectedVersion: "1.35.0",
		},
		{
			name:            "same version as binary does not override",
			kopsBaseURL:     fmt.Sprintf("https://example.com/kops/%s", origVersion),
			expectedVersion: origVersion,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kops.Version = origVersion
			kopsBaseURL = nil
			t.Setenv("KOPS_BASE_URL", tc.kopsBaseURL)

			_, err := BaseURL()
			if err != nil {
				t.Fatalf("BaseURL() error: %v", err)
			}
			if kops.Version != tc.expectedVersion {
				t.Errorf("kops.Version = %q, want %q", kops.Version, tc.expectedVersion)
			}
		})
	}
}

func Test_BuildMirroredAsset(t *testing.T) {
	tests := []struct {
		url      string
		hash     string
		expected []string
	}{
		{
			url: "https://artifacts.k8s.io/binaries/kops/%s/linux/amd64/nodeup",
			expected: []string{
				"https://artifacts.k8s.io/binaries/kops/" + kops.Version + "/linux/amd64/nodeup",
				"https://github.com/kubernetes/kops/releases/download/v" + kops.Version + "/nodeup-linux-amd64",
			},
		},
		{
			url: "https://artifacts.k8s.io/binaries/kops/%s/linux/arm64/nodeup",
			expected: []string{
				"https://artifacts.k8s.io/binaries/kops/" + kops.Version + "/linux/arm64/nodeup",
				"https://github.com/kubernetes/kops/releases/download/v" + kops.Version + "/nodeup-linux-arm64",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			h := hashing.MustFromString("0000000000000000000000000000000000000000000000000000000000000000")
			u, err := url.Parse(fmt.Sprintf(tc.url, kops.Version))
			if err != nil {
				t.Errorf("cannot parse URL: %s", fmt.Sprintf(tc.url, kops.Version))
				return
			}
			asset := &assets.FileAsset{
				DownloadURL:  u,
				CanonicalURL: u,
				SHAValue:     h,
			}
			actual := assets.BuildMirroredAsset(asset)

			if !reflect.DeepEqual(actual.Locations, tc.expected) {
				t.Errorf("Locations differ:\nActual: %+v\nExpect: %+v", actual.Locations, tc.expected)
				return
			}
		})
	}
}

func TestNodeUpAssetOCIStagesRawAndXZ(t *testing.T) {
	originalVersion := kops.Version
	originalBaseURL := kopsBaseURL
	originalNodeUpAsset := nodeUpAsset
	t.Cleanup(func() {
		kops.Version = originalVersion
		kopsBaseURL = originalBaseURL
		nodeUpAsset = originalNodeUpAsset
	})

	baseDir := filepath.Join(t.TempDir(), "v1.37.0")
	assetDir := filepath.Join(baseDir, "linux", "amd64")
	if err := os.MkdirAll(assetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := []byte("nodeup bytes")
	compressed := []byte("xz nodeup bytes")
	rawHash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compressedHash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"nodeup":           raw,
		"nodeup.sha256":    []byte(rawHash.Hex()),
		"nodeup.xz":        compressed,
		"nodeup.xz.sha256": []byte(compressedHash.Hex()),
	} {
		if err := os.WriteFile(filepath.Join(assetDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("KOPS_BASE_URL", (&url.URL{Scheme: "file", Path: baseDir}).String())
	kopsBaseURL = nil
	nodeUpAsset = nil
	fileRepository := "oci://registry.example.com/optional-prefix"
	builder := assets.NewAssetBuilder(vfs.NewVFSContext(), &apiskops.AssetsSpec{FileRepository: &fileRepository}, true)
	asset, err := NodeUpAsset(builder, architectures.ArchitectureAmd64)
	if err != nil {
		t.Fatal(err)
	}

	if !asset.Hash.Equal(rawHash) {
		t.Errorf("uncompressed hash = %s, want %s", asset.Hash, rawHash)
	}
	if len(asset.Locations) != 1 || asset.Locations[0] != "oci://registry.example.com/optional-prefix/nodeup:v1.37.0-amd64" {
		t.Errorf("locations = %v", asset.Locations)
	}
	fileAssets := builder.FileAssets()
	if len(fileAssets) != 2 {
		t.Fatalf("file assets = %d, want 2", len(fileAssets))
	}
	wantHashes := map[string]*hashing.Hash{
		"nodeup":    rawHash,
		"nodeup.xz": compressedHash,
	}
	for _, fileAsset := range fileAssets {
		name := filepath.Base(fileAsset.CanonicalURL.Path)
		wantHash, ok := wantHashes[name]
		if !ok {
			t.Errorf("unexpected staged source %q", fileAsset.CanonicalURL)
			continue
		}
		if !fileAsset.SHAValue.Equal(wantHash) {
			t.Errorf("staged hash for %s = %s, want %s", name, fileAsset.SHAValue, wantHash)
		}
		if got := fileAsset.DownloadURL.String(); got != "oci://registry.example.com/optional-prefix/nodeup:v1.37.0-amd64" {
			t.Errorf("staged target for %s = %q", name, got)
		}
		delete(wantHashes, name)
	}
	if len(wantHashes) != 0 {
		t.Errorf("missing staged sources: %v", wantHashes)
	}
}
