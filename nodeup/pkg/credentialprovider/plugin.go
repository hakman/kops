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

// Package credentialprovider implements the kubelet exec-based image
// credential provider protocol for the registries of the clouds supported
// by kOps, so that nodeup itself can be invoked as the provider binary
// instead of downloading a separate one on every node.
//
// The provider implementations are adapted from their upstream sources:
// ECR from k8s.io/cloud-provider-aws (cmd/ecr-credential-provider) and
// GCP from k8s.io/cloud-provider-gcp (cmd/auth-provider-gcp).
package credentialprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"k8s.io/klog/v2"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

// Provider fetches registry credentials for the given image reference.
type Provider interface {
	GetCredentials(ctx context.Context, image string) (*v1.CredentialProviderResponse, error)
}

// RunPlugin reads a v1.CredentialProviderRequest from r, asks the provider
// for credentials and writes a v1.CredentialProviderResponse to w.
// Only the JSON response may be written to w; the kubelet parses the
// plugin's stdout.
func RunPlugin(ctx context.Context, provider Provider, r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading request: %w", err)
	}

	var request v1.CredentialProviderRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return fmt.Errorf("unmarshaling request: %w", err)
	}

	if request.APIVersion != v1.SchemeGroupVersion.String() {
		return fmt.Errorf("unsupported request apiVersion %q, expected %q", request.APIVersion, v1.SchemeGroupVersion.String())
	}
	if request.Kind != "CredentialProviderRequest" {
		return fmt.Errorf("unsupported request kind %q, expected CredentialProviderRequest", request.Kind)
	}
	if request.Image == "" {
		return errors.New("image in request was empty")
	}

	response, err := provider.GetCredentials(ctx, request.Image)
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("CredentialProviderResponse from provider was nil")
	}

	response.Kind = "CredentialProviderResponse"
	response.APIVersion = v1.SchemeGroupVersion.String()

	encoded, err := json.Marshal(response)
	if err != nil {
		// The marshaling error is intentionally not wrapped so as to not
		// leak credentials into the logs.
		return errors.New("marshaling response")
	}

	if _, err := w.Write(encoded); err != nil {
		return fmt.Errorf("writing response: %w", err)
	}
	return nil
}

// Main runs the given provider as a kubelet credential provider plugin,
// speaking the exec plugin protocol on stdin/stdout. It never returns.
func Main(provider Provider) {
	// Logging must go to stderr: stdout is reserved for the JSON response.
	klog.InitFlags(nil)
	if err := RunPlugin(context.Background(), provider, os.Stdin, os.Stdout); err != nil {
		klog.Errorf("Error running credential provider plugin: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}
