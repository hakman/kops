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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"k8s.io/kops/util/pkg/vfs"
)

var ociGet = remote.Get
var ociWrite = remote.Write

type httpsOnlyRegistryTransport struct {
	inner http.RoundTripper
}

func (t *httpsOnlyRegistryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" {
		return nil, fmt.Errorf("OCI registry request must use HTTPS: %s", request.URL)
	}
	return t.inner.RoundTrip(request)
}

type ociAssetSource struct {
	location string
	sha256   string
}

type copyOCIAsset struct {
	sources []ociAssetSource
	target  string
	vfs     *vfs.VFSContext
}

func (c *copyOCIAsset) addSource(source ociAssetSource) {
	for _, existing := range c.sources {
		if existing.sha256 == source.sha256 {
			return
		}
	}
	c.sources = append(c.sources, source)
}

func (c *copyOCIAsset) Run() error {
	location, err := url.Parse(c.target)
	if err != nil || location.Scheme != "oci" || location.Host == "" || location.User != nil || location.RawQuery != "" || location.Fragment != "" {
		return fmt.Errorf("invalid OCI target %q", c.target)
	}
	ref, err := name.NewTag(location.Host+location.Path, name.StrictValidation)
	if err != nil {
		return fmt.Errorf("invalid OCI target %q: %w", c.target, err)
	}

	options := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(&httpsOnlyRegistryTransport{inner: remote.DefaultTransport}),
	}
	sources := append([]ociAssetSource(nil), c.sources...)
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].sha256 < sources[j].sha256
	})
	digests := make([]string, 0, len(sources))
	for _, source := range sources {
		digests = append(digests, source.sha256)
	}
	if len(digests) == 0 {
		return fmt.Errorf("OCI target %q has no source files", c.target)
	}

	present, err := c.tagContainsBlobs(ref, digests, options)
	if err != nil {
		return err
	}
	if present {
		return nil
	}

	layers := make([]v1.Layer, 0, len(sources))
	for _, source := range sources {
		data, err := c.vfs.ReadFile(source.location)
		if err != nil {
			return fmt.Errorf("reading %q: %w", source.location, err)
		}
		layer := &fileBlob{data: data}
		digest, err := layer.Digest()
		if err != nil {
			return err
		}
		if digest.Hex != source.sha256 {
			return fmt.Errorf("source %q has sha256:%s, expected sha256:%s", source.location, digest.Hex, source.sha256)
		}
		layers = append(layers, layer)
	}

	image, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return fmt.Errorf("creating OCI manifest: %w", err)
	}
	image = mutate.MediaType(image, types.OCIManifestSchema1)
	image = mutate.ConfigMediaType(image, types.OCIConfigJSON)
	return c.ensureTag(ref, image, digests, options)
}

func (c *copyOCIAsset) ensureTag(ref name.Tag, image v1.Image, digests []string, options []remote.Option) error {
	present, err := c.tagContainsBlobs(ref, digests, options)
	if err != nil {
		return err
	}
	if present {
		return nil
	}
	if err := ociWrite(ref, image, options...); err != nil {
		return fmt.Errorf("pushing OCI tag %q: %w", ref.Name(), err)
	}
	present, err = c.tagContainsBlobs(ref, digests, options)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("OCI tag %q did not retain layer digest(s) %s", ref.Name(), formatDigests(digests))
	}
	return nil
}

func (c *copyOCIAsset) tagContainsBlobs(ref name.Reference, digests []string, options []remote.Option) (bool, error) {
	descriptor, err := ociGet(ref, options...)
	if err != nil {
		var registryError *transport.Error
		if errors.As(err, &registryError) && registryError.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("reading OCI tag %q: %w", ref.Name(), err)
	}
	var manifest v1.Manifest
	if err := json.Unmarshal(descriptor.Manifest, &manifest); err != nil {
		return false, fmt.Errorf("decoding OCI tag %q: %w", ref.Name(), err)
	}
	existingDigests := make([]string, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		existingDigests = append(existingDigests, layer.Digest.String())
	}
	expectedDigests := make([]string, 0, len(digests))
	for _, digest := range digests {
		expectedDigests = append(expectedDigests, "sha256:"+digest)
	}
	sort.Strings(existingDigests)
	sort.Strings(expectedDigests)
	if len(existingDigests) == len(expectedDigests) && strings.Join(existingDigests, ",") == strings.Join(expectedDigests, ",") {
		return true, nil
	}
	const remediation = "publish changed bytes under a distinct asset version, or remove the conflicting tag only after verifying that it is no longer needed"
	expected := "expected layer digest(s) " + formatDigests(digests)
	if len(digests) == 1 {
		expected = "expected sha256:" + digests[0]
	}
	if len(manifest.Layers) == 0 {
		return false, fmt.Errorf(
			"OCI tag %q references media type %q with no file layer, %s; %s",
			ref.Name(), descriptor.MediaType, expected, remediation)
	}
	return false, fmt.Errorf(
		"OCI tag %q references layer digest(s) %s, %s; %s",
		ref.Name(), strings.Join(existingDigests, ", "), expected, remediation)
}

func formatDigests(digests []string) string {
	formatted := make([]string, 0, len(digests))
	for _, digest := range digests {
		formatted = append(formatted, "sha256:"+digest)
	}
	return strings.Join(formatted, ", ")
}

// fileBlob exposes the source bytes unchanged as an OCI layer.
type fileBlob struct {
	data []byte
}

func (l *fileBlob) Digest() (v1.Hash, error) {
	hash, _, err := v1.SHA256(bytes.NewReader(l.data))
	return hash, err
}

func (l *fileBlob) DiffID() (v1.Hash, error) {
	return l.Digest()
}

func (l *fileBlob) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.data)), nil
}

func (l *fileBlob) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.data)), nil
}

func (l *fileBlob) Size() (int64, error) {
	return int64(len(l.data)), nil
}

func (l *fileBlob) MediaType() (types.MediaType, error) {
	return types.MediaType("application/octet-stream"), nil
}
