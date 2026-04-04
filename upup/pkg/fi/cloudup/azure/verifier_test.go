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

package azure

import (
	"encoding/base64"
	"testing"

	"k8s.io/kops/pkg/bootstrap"
)

// TestVerifyToken covers the early rejection paths: wrong prefix (different
// cloud verifier), malformed two-part payload, mismatched subscription/RG,
// and unparseable PKCS7.
func TestVerifyToken(t *testing.T) {
	matchingResourceID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	wrongSubResourceID := "/subscriptions/other/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	wrongRGResourceID := "/subscriptions/sub/resourceGroups/other/providers/Microsoft.Compute/virtualMachines/vm"
	invalidPKCS7 := base64.StdEncoding.EncodeToString([]byte("not-pkcs7"))

	testCases := []struct {
		name    string
		token   string
		wantErr error // explicit error to compare with ==; nil means "any non-nil error"
	}{
		{"wrong prefix", "x-aws-sts something", bootstrap.ErrNotThisVerifier},
		{"missing signature", AzureAuthenticationTokenPrefix + "no-space-here", nil},
		{"subscription mismatch", AzureAuthenticationTokenPrefix + wrongSubResourceID + " " + invalidPKCS7, nil},
		{"resource group mismatch", AzureAuthenticationTokenPrefix + wrongRGResourceID + " " + invalidPKCS7, nil},
		{"invalid PKCS7", AzureAuthenticationTokenPrefix + matchingResourceID + " " + invalidPKCS7, nil},
	}

	v := &azureVerifier{
		client: &client{
			subscriptionID: "sub",
			resourceGroup:  "rg",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.VerifyToken(nil, nil, tc.token, nil)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Errorf("expected %v, got: %v", tc.wantErr, err)
				}
				return
			}
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}
