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
	"math/big"

	"k8s.io/klog/v2"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/pki"
)

// ParseKeyset parses a Keyset API object into a Keyset
func ParseKeyset(o *kops.Keyset) (*Keyset, error) {
	name := o.Name

	keyset := &Keyset{
		Items: make(map[string]*KeysetItem),
	}

	for _, key := range o.Spec.Keys {
		ki := &KeysetItem{
			Id: key.Id,
		}
		if key.DistrustTimestamp != nil {
			distrustTimestamp := key.DistrustTimestamp.Time
			ki.DistrustTimestamp = &distrustTimestamp
		}
		if len(key.PublicMaterial) != 0 {
			cert, err := pki.ParsePEMCertificate(key.PublicMaterial)
			if err != nil {
				klog.Warningf("key public material was %s", key.PublicMaterial)
				return nil, fmt.Errorf("error loading certificate %s/%s: %v", name, key.Id, err)
			}
			ki.Certificate = cert
		}

		if len(key.PrivateMaterial) != 0 {
			privateKey, err := pki.ParsePEMPrivateKey(key.PrivateMaterial)
			if err != nil {
				return nil, fmt.Errorf("error loading private key %s/%s: %v", name, key.Id, err)
			}
			ki.PrivateKey = privateKey
		}

		keyset.Items[key.Id] = ki
	}

	keyset.Primary = keyset.Items[FindPrimary(o).Id]

	return keyset, nil
}

// FindPrimary returns the primary KeysetItem in the Keyset
func FindPrimary(keyset *kops.Keyset) *kops.KeysetItem {
	var primary *kops.KeysetItem
	var primaryVersion *big.Int

	primaryId := keyset.Spec.PrimaryID

	for i := range keyset.Spec.Keys {
		item := &keyset.Spec.Keys[i]
		if item.DistrustTimestamp != nil {
			continue
		}

		version, ok := big.NewInt(0).SetString(item.Id, 10)
		if !ok {
			klog.Warningf("Ignoring key item with non-integer version: %q", item.Id)
			continue
		}

		if item.Id == primaryId {
			return item
		}

		if primaryVersion == nil || version.Cmp(primaryVersion) > 0 {
			primary = item
			primaryVersion = version
		}
	}
	return primary
}
