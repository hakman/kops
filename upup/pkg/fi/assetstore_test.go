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
	"maps"
	"regexp"
	"slices"
	"testing"
)

func TestFindArchiveMatches(t *testing.T) {
	cni := &Source{URL: "https://github.com/containernetworking/plugins/releases/download/v1.9.1/cni-plugins-linux-amd64-v1.9.1.tgz"}
	crictl := &Source{URL: "https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.34.0/crictl-v1.34.0-linux-amd64.tar.gz"}
	kubelet := &Source{URL: "https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubelet"}

	a := &AssetStore{assets: []*asset{
		{Key: "cni-plugins-linux-amd64-v1.9.1.tgz", AssetPath: cni.URL, source: cni},
		{Key: "bridge", AssetPath: "bridge", source: &Source{Parent: cni, ExtractFromArchive: "bridge"}},
		{Key: "portmap", AssetPath: "portmap", source: &Source{Parent: cni, ExtractFromArchive: "portmap"}},
		{Key: "crictl", AssetPath: "crictl", source: &Source{Parent: crictl, ExtractFromArchive: "crictl"}},
		{Key: "kubelet", AssetPath: kubelet.URL, source: kubelet},
	}}

	got := slices.Sorted(maps.Keys(a.FindArchiveMatches(regexp.MustCompile(`^cni-plugins-`))))
	want := []string{"bridge", "portmap"}
	if !slices.Equal(got, want) {
		t.Errorf("FindArchiveMatches() = %v, want %v", got, want)
	}
}
