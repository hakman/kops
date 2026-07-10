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
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kops/pkg/apis/kops"
	"sigs.k8s.io/yaml"
)

// keysetWireFormat is the wire format of a keyset.yaml bundle, matching the
// v1alpha2 Keyset API type.  Keyset bundles are always written as v1alpha2,
// and are encoded and decoded by hand rather than through kopscodecs so that
// nodeup does not need to link the full kops API scheme with all its
// versions and conversions.
type keysetWireFormat struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec keysetWireSpec `json:"spec,omitempty"`
}

type keysetWireSpec struct {
	// Type is the type of the Keyset (PKI keypair, or secret token)
	Type kops.KeysetType `json:"type,omitempty"`

	// PrimaryID is the id of the key used to make new signatures.
	// The v1alpha2 wire format uses the field name "primaryId", where the
	// internal type uses "primaryID".
	PrimaryID string `json:"primaryId,omitempty"`

	// Keys is the set of keys that make up the keyset.
	// The internal KeysetItem has the same wire format as the v1alpha2 one.
	Keys []kops.KeysetItem `json:"keys,omitempty"`
}

// parseKeysetBundle parses a keyset.yaml bundle.
func parseKeysetBundle(data []byte) (*kops.Keyset, error) {
	wire := &keysetWireFormat{}
	if err := yaml.Unmarshal(data, wire); err != nil {
		return nil, fmt.Errorf("error parsing keyset: %v", err)
	}

	gv, err := schema.ParseGroupVersion(wire.APIVersion)
	if err != nil {
		return nil, fmt.Errorf("error parsing apiVersion %q: %v", wire.APIVersion, err)
	}

	// kOps was originally registered under the "kops" group;
	// treat it as an alias for "kops.k8s.io".
	group := gv.Group
	if group == "kops" {
		group = "kops.k8s.io"
	}

	if group != kops.GroupName || wire.Kind != "Keyset" {
		return nil, fmt.Errorf("object was not a keyset, was a %q", wire.APIVersion+"/"+wire.Kind)
	}
	if gv.Version != keysetFormatLatest {
		return nil, fmt.Errorf("unsupported keyset version %q", wire.APIVersion)
	}

	o := &kops.Keyset{
		ObjectMeta: wire.ObjectMeta,
		Spec: kops.KeysetSpec{
			Type:      wire.Spec.Type,
			PrimaryID: wire.Spec.PrimaryID,
			Keys:      wire.Spec.Keys,
		},
	}
	return o, nil
}

// serializeKeysetBundle converts a Keyset bundle to yaml, for writing to VFS.
func serializeKeysetBundle(o *kops.Keyset) ([]byte, error) {
	wire := &keysetWireFormat{
		TypeMeta: metav1.TypeMeta{
			APIVersion: kops.GroupName + "/" + keysetFormatLatest,
			Kind:       "Keyset",
		},
		ObjectMeta: o.ObjectMeta,
		Spec: keysetWireSpec{
			Type:      o.Spec.Type,
			PrimaryID: o.Spec.PrimaryID,
			Keys:      o.Spec.Keys,
		},
	}

	objectData, err := yaml.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("error serializing keyset: %v", err)
	}
	return objectData, nil
}
