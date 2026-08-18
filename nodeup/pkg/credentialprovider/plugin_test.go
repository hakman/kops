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
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

type staticProvider struct {
	response *v1.CredentialProviderResponse
	err      error
}

func (s *staticProvider) GetCredentials(ctx context.Context, image string) (*v1.CredentialProviderResponse, error) {
	return s.response, s.err
}

func TestRunPlugin(t *testing.T) {
	testcases := []struct {
		name          string
		request       string
		response      *v1.CredentialProviderResponse
		expectedError string
	}{
		{
			name:    "success",
			request: `{"apiVersion":"credentialprovider.kubelet.k8s.io/v1","kind":"CredentialProviderRequest","image":"123456789123.dkr.ecr.us-west-2.amazonaws.com/foo:latest"}`,
			response: &v1.CredentialProviderResponse{
				CacheKeyType: v1.RegistryPluginCacheKeyType,
				Auth: map[string]v1.AuthConfig{
					"123456789123.dkr.ecr.us-west-2.amazonaws.com": {Username: "user", Password: "pass"},
				},
			},
		},
		{
			name:          "unsupported apiVersion",
			request:       `{"apiVersion":"credentialprovider.kubelet.k8s.io/v1beta1","kind":"CredentialProviderRequest","image":"foo"}`,
			expectedError: "unsupported request apiVersion",
		},
		{
			name:          "unsupported kind",
			request:       `{"apiVersion":"credentialprovider.kubelet.k8s.io/v1","kind":"Foo","image":"foo"}`,
			expectedError: "unsupported request kind",
		},
		{
			name:          "empty image",
			request:       `{"apiVersion":"credentialprovider.kubelet.k8s.io/v1","kind":"CredentialProviderRequest"}`,
			expectedError: "image in request was empty",
		},
		{
			name:          "invalid JSON",
			request:       `not json`,
			expectedError: "unmarshaling request",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			provider := &staticProvider{response: testcase.response}
			var out bytes.Buffer

			err := RunPlugin(context.TODO(), provider, strings.NewReader(testcase.request), &out)

			if testcase.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got none", testcase.expectedError)
				}
				if !strings.Contains(err.Error(), testcase.expectedError) {
					t.Fatalf("expected error containing %q, got %q", testcase.expectedError, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var response v1.CredentialProviderResponse
			if err := json.Unmarshal(out.Bytes(), &response); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if response.APIVersion != "credentialprovider.kubelet.k8s.io/v1" {
				t.Errorf("unexpected response apiVersion: %s", response.APIVersion)
			}
			if response.Kind != "CredentialProviderResponse" {
				t.Errorf("unexpected response kind: %s", response.Kind)
			}
			if response.Auth["123456789123.dkr.ecr.us-west-2.amazonaws.com"].Username != "user" {
				t.Errorf("unexpected auth in response: %v", response.Auth)
			}
		})
	}
}
