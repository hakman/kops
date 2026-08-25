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

package assetcopy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"k8s.io/kops/pkg/assets"
	"k8s.io/kops/util/pkg/hashing"
	"k8s.io/kops/util/pkg/vfs"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestHTTPSOnlyRegistryTransport(t *testing.T) {
	called := false
	transport := &httpsOnlyRegistryTransport{inner: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}

	request, err := http.NewRequest(http.MethodGet, "http://localhost:5000/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("RoundTrip() error = %v, want HTTPS error", err)
	}
	if called {
		t.Fatal("HTTP request reached the registry transport")
	}

	request, err = http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if !called {
		t.Fatal("HTTPS request did not reach the registry transport")
	}
}

func TestCopyOCIAsset(t *testing.T) {
	content := []byte("unchanged file bytes")
	hash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "asset")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}

	originalGet, originalWrite := ociGet, ociWrite
	t.Cleanup(func() { ociGet, ociWrite = originalGet, originalWrite })
	var writes []string
	manifests := make(map[string]*remote.Descriptor)
	ociGet = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		descriptor := manifests[ref.Name()]
		if descriptor == nil {
			return nil, &transport.Error{StatusCode: http.StatusNotFound}
		}
		return descriptor, nil
	}
	ociWrite = func(ref name.Reference, image v1.Image, _ ...remote.Option) error {
		writes = append(writes, ref.Name())
		manifest, err := image.Manifest()
		if err != nil {
			t.Fatal(err)
		}
		if manifest.MediaType != types.OCIManifestSchema1 || manifest.Config.MediaType != types.OCIConfigJSON {
			t.Fatalf("manifest is not OCI: %#v", manifest)
		}
		layers, err := image.Layers()
		if err != nil || len(layers) != 1 {
			t.Fatalf("Layers() = %d, %v", len(layers), err)
		}
		reader, err := layers[0].Compressed()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		got, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("layer bytes = %q, want %q", got, content)
		}
		manifests[ref.Name()] = descriptorForLayer(t, manifest.Layers[0].Digest.Hex)
		return nil
	}

	task := &copyOCIAsset{
		sources: []ociAssetSource{{location: source, sha256: hash.Hex()}},
		target:  "oci://registry.example.com/prefix/tool:v1.2.3-amd64",
		vfs:     vfs.Context,
	}
	if err := task.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := task.Run(); err != nil {
		t.Fatalf("idempotent Run() error = %v", err)
	}
	wantWrites := []string{"registry.example.com/prefix/tool:v1.2.3-amd64"}
	if strings.Join(writes, ",") != strings.Join(wantWrites, ",") {
		t.Fatalf("registry writes=%v, want %v", writes, wantWrites)
	}
}

func TestCopyOCIAssetStagesAllSourcesUnderOneTag(t *testing.T) {
	raw := []byte("raw nodeup bytes")
	compressed := []byte("xz nodeup bytes")
	directory := t.TempDir()
	target, err := url.Parse("oci://registry.example.com/prefix/nodeup:v1.2.3-amd64")
	if err != nil {
		t.Fatal(err)
	}
	fileAssets := make([]*assets.FileAsset, 0, 2)
	wantContent := map[string]bool{string(raw): true, string(compressed): true}
	for name, content := range map[string][]byte{"nodeup": raw, "nodeup.xz": compressed} {
		source := filepath.Join(directory, name)
		if err := os.WriteFile(source, content, 0o600); err != nil {
			t.Fatal(err)
		}
		hash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		fileAssets = append(fileAssets, &assets.FileAsset{
			CanonicalURL: &url.URL{Path: source},
			DownloadURL:  target,
			SHAValue:     hash,
		})
	}
	semanticTag := target.Host + target.Path

	originalGet, originalWrite := ociGet, ociWrite
	t.Cleanup(func() { ociGet, ociWrite = originalGet, originalWrite })
	manifests := make(map[string]*remote.Descriptor)
	writes := 0
	ociGet = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		if descriptor := manifests[ref.Name()]; descriptor != nil {
			return descriptor, nil
		}
		return nil, &transport.Error{StatusCode: http.StatusNotFound}
	}
	ociWrite = func(ref name.Reference, image v1.Image, _ ...remote.Option) error {
		writes++
		if ref.Name() != semanticTag {
			return fmt.Errorf("unexpected tag %s", ref.Name())
		}
		layers, err := image.Layers()
		if err != nil {
			return err
		}
		if len(layers) != 2 {
			return fmt.Errorf("Layers() = %d, want 2", len(layers))
		}
		for _, layer := range layers {
			reader, err := layer.Compressed()
			if err != nil {
				return err
			}
			content, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil {
				return err
			}
			if !wantContent[string(content)] {
				return fmt.Errorf("unexpected layer content %q", content)
			}
		}
		manifest, err := image.Manifest()
		if err != nil {
			return err
		}
		digests := make([]string, 0, len(manifest.Layers))
		for _, layer := range manifest.Layers {
			digests = append(digests, layer.Digest.Hex)
		}
		manifests[ref.Name()] = descriptorForLayers(t, digests...)
		return nil
	}

	if err := Copy(nil, fileAssets, vfs.Context, nil); err != nil {
		t.Fatalf("Copy() error = %v", err)
	}
	if writes != 1 {
		t.Fatalf("writes = %d, want one semantic tag", writes)
	}
	if err := Copy(nil, fileAssets, vfs.Context, nil); err != nil {
		t.Fatalf("idempotent Copy() error = %v", err)
	}
	if writes != 1 {
		t.Fatalf("idempotent copy wrote %d additional manifests", writes-1)
	}
}

func TestCopyOCIAssetDoesNotReadSourceWhenTagsMatch(t *testing.T) {
	hash := strings.Repeat("a", 64)
	originalGet, originalWrite := ociGet, ociWrite
	t.Cleanup(func() { ociGet, ociWrite = originalGet, originalWrite })
	ociGet = func(_ name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		return descriptorForLayer(t, hash), nil
	}
	ociWrite = func(ref name.Reference, _ v1.Image, _ ...remote.Option) error {
		t.Fatalf("unexpected write of existing tag %s", ref.Name())
		return nil
	}

	task := &copyOCIAsset{
		sources: []ociAssetSource{{location: filepath.Join(t.TempDir(), "does-not-exist"), sha256: hash}},
		target:  "oci://registry.example.com/prefix/tool:v1.2.3-amd64",
		vfs:     vfs.Context,
	}
	if err := task.Run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestCopyOCIAssetRejectsTagCollision(t *testing.T) {
	hash := strings.Repeat("a", 64)
	originalGet, originalWrite := ociGet, ociWrite
	t.Cleanup(func() { ociGet, ociWrite = originalGet, originalWrite })
	semanticTag := "registry.example.com/tool:v1-amd64"
	ociGet = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		if ref.Name() != semanticTag {
			t.Fatalf("unexpected tag read: %s", ref.Name())
		}
		return descriptorForLayer(t, strings.Repeat("f", 64)), nil
	}
	ociWrite = func(ref name.Reference, _ v1.Image, _ ...remote.Option) error {
		t.Fatalf("conflicting tag was overwritten: %s", ref.Name())
		return nil
	}

	task := &copyOCIAsset{sources: []ociAssetSource{{location: filepath.Join(t.TempDir(), "does-not-exist"), sha256: hash}}, target: "oci://registry.example.com/tool:v1-amd64", vfs: vfs.Context}
	err := task.Run()
	for _, want := range []string{
		semanticTag,
		"sha256:" + strings.Repeat("f", 64),
		"expected sha256:" + hash,
		"distinct asset version",
		"remove the conflicting tag only after verifying that it is no longer needed",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Run() error = %v, want %q", err, want)
		}
	}
}

func TestCopyOCIAssetReportsConcurrentTagChange(t *testing.T) {
	content := []byte("concurrent source")
	hash, err := hashing.HashAlgorithmSHA256.Hash(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "asset")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}

	originalGet, originalWrite := ociGet, ociWrite
	t.Cleanup(func() { ociGet, ociWrite = originalGet, originalWrite })
	semanticTag := "registry.example.com/tool:v1-amd64"
	semanticWritten := false
	ociGet = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		if ref.Name() != semanticTag {
			t.Fatalf("unexpected tag read: %s", ref.Name())
		}
		if semanticWritten {
			return descriptorForLayer(t, strings.Repeat("f", 64)), nil
		}
		return nil, &transport.Error{StatusCode: http.StatusNotFound}
	}
	ociWrite = func(ref name.Reference, _ v1.Image, _ ...remote.Option) error {
		if ref.Name() != semanticTag {
			t.Fatalf("unexpected tag write: %s", ref.Name())
		}
		semanticWritten = true
		return nil
	}

	task := &copyOCIAsset{sources: []ociAssetSource{{location: source, sha256: hash.Hex()}}, target: "oci://" + semanticTag, vfs: vfs.Context}
	err = task.Run()
	if err == nil || !strings.Contains(err.Error(), semanticTag) ||
		!strings.Contains(err.Error(), "sha256:"+strings.Repeat("f", 64)) ||
		!strings.Contains(err.Error(), "expected sha256:"+hash.Hex()) {
		t.Fatalf("Run() error = %v, want concurrent tag collision with both digests", err)
	}
}

func TestCopyOCIAssetReportsManifestWithoutLayers(t *testing.T) {
	const tag = "registry.example.com/tool:v1-amd64"
	expected := strings.Repeat("a", 64)
	index := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
	}
	manifest, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}

	originalGet := ociGet
	t.Cleanup(func() { ociGet = originalGet })
	ociGet = func(ref name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		return &remote.Descriptor{
			Descriptor: v1.Descriptor{MediaType: types.OCIImageIndex},
			Manifest:   manifest,
		}, nil
	}

	task := &copyOCIAsset{}
	_, err = task.tagContainsBlobs(mustTag(t, tag), []string{expected}, nil)
	for _, want := range []string{tag, string(types.OCIImageIndex), "no file layer", "expected sha256:" + expected} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("tagContainsBlobs() error = %v, want %q", err, want)
		}
	}
}

func descriptorForLayer(t *testing.T, digest string) *remote.Descriptor {
	return descriptorForLayers(t, digest)
}

func descriptorForLayers(t *testing.T, digests ...string) *remote.Descriptor {
	t.Helper()
	manifest := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: v1.Descriptor{
			MediaType: types.OCIConfigJSON,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)},
			Size:      2,
		},
	}
	for _, digest := range digests {
		manifest.Layers = append(manifest.Layers, v1.Descriptor{
			MediaType: types.MediaType("application/octet-stream"),
			Digest:    v1.Hash{Algorithm: "sha256", Hex: digest},
			Size:      1,
		})
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return &remote.Descriptor{
		Descriptor: v1.Descriptor{MediaType: types.OCIManifestSchema1},
		Manifest:   b,
	}
}

func mustTag(t *testing.T, ref string) name.Tag {
	t.Helper()
	tag, err := name.NewTag(ref, name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	return tag
}
