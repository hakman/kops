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
	"reflect"
	"strings"
	"testing"

	"k8s.io/kops/pkg/apis/kops"
)

func TestParseKeysetBundle(t *testing.T) {
	expected := &kops.Keyset{
		Spec: kops.KeysetSpec{
			Type:      kops.SecretTypeKeypair,
			PrimaryID: "2",
			Keys: []kops.KeysetItem{
				{Id: "1", PublicMaterial: []byte("public"), PrivateMaterial: []byte("private")},
				{Id: "2", PublicMaterial: []byte("public2")},
			},
		},
	}
	expected.Name = "kubernetes-ca"

	grid := []struct {
		name     string
		data     string
		expected *kops.Keyset
		errMsg   string
	}{
		{
			name: "current format",
			data: `
apiVersion: kops.k8s.io/v1alpha2
kind: Keyset
metadata:
  name: kubernetes-ca
spec:
  keys:
  - id: "1"
    privateMaterial: cHJpdmF0ZQ==
    publicMaterial: cHVibGlj
  - id: "2"
    publicMaterial: cHVibGljMg==
  primaryId: "2"
  type: Keypair
`,
			expected: expected,
		},
		{
			name: "legacy kops group",
			data: `
apiVersion: kops/v1alpha2
kind: Keyset
metadata:
  name: kubernetes-ca
spec:
  keys:
  - id: "1"
    privateMaterial: cHJpdmF0ZQ==
    publicMaterial: cHVibGlj
  - id: "2"
    publicMaterial: cHVibGljMg==
  primaryId: "2"
  type: Keypair
`,
			expected: expected,
		},
		{
			name:     "json format",
			data:     `{"apiVersion": "kops.k8s.io/v1alpha2", "kind": "Keyset", "metadata": {"name": "kubernetes-ca"}, "spec": {"keys": [{"id": "1", "privateMaterial": "cHJpdmF0ZQ==", "publicMaterial": "cHVibGlj"}, {"id": "2", "publicMaterial": "cHVibGljMg=="}], "primaryId": "2", "type": "Keypair"}}`,
			expected: expected,
		},
		{
			name:   "wrong kind",
			data:   "apiVersion: kops.k8s.io/v1alpha2\nkind: Cluster\n",
			errMsg: "object was not a keyset",
		},
		{
			name:   "wrong group",
			data:   "apiVersion: v1\nkind: Keyset\n",
			errMsg: "object was not a keyset",
		},
		{
			name:   "missing apiVersion",
			data:   "kind: Keyset\n",
			errMsg: "object was not a keyset",
		},
		{
			name:   "unsupported version",
			data:   "apiVersion: kops.k8s.io/v1alpha3\nkind: Keyset\n",
			errMsg: "unsupported keyset version",
		},
		{
			name:   "not yaml",
			data:   "{{{",
			errMsg: "error parsing keyset",
		},
	}

	for _, tc := range grid {
		t.Run(tc.name, func(t *testing.T) {
			o, err := parseKeysetBundle([]byte(tc.data))
			if tc.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errMsg) {
					t.Fatalf("expected error containing %q, got %v", tc.errMsg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(o, tc.expected) {
				t.Fatalf("unexpected keyset:\n  actual:   %+v\n  expected: %+v", o, tc.expected)
			}
		})
	}
}

func TestKeysetBundleRoundTrip(t *testing.T) {
	o := &kops.Keyset{
		Spec: kops.KeysetSpec{
			Type:      kops.SecretTypeKeypair,
			PrimaryID: "2",
			Keys: []kops.KeysetItem{
				{Id: "1", PublicMaterial: []byte("public"), PrivateMaterial: []byte("private")},
				{Id: "2", PublicMaterial: []byte("public2")},
			},
		},
	}
	o.Name = "kubernetes-ca"

	data, err := serializeKeysetBundle(o)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := parseKeysetBundle(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(parsed, o) {
		t.Fatalf("keyset did not round-trip:\n  actual:   %+v\n  expected: %+v", parsed, o)
	}
}
