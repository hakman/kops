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

package oci

import "testing"

func TestIsRepositoryComponent(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "asset", want: true},
		{value: "asset.name", want: true},
		{value: "asset_name", want: true},
		{value: "asset__name", want: true},
		{value: "asset--name", want: true},
		{value: "Asset", want: false},
		{value: "-asset", want: false},
		{value: "asset..name", want: false},
	} {
		if got := IsRepositoryComponent(test.value); got != test.want {
			t.Errorf("IsRepositoryComponent(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}
