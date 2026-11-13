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

package model

import (
	"maps"
	"slices"
	"testing"

	kopsmodel "k8s.io/kops/pkg/apis/kops/model"
	"k8s.io/kops/pkg/apis/nodeup"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/util/pkg/distributions"
)

func TestLogrotateBuilder(t *testing.T) {
	componentFiles := []string{
		"File//etc/logrotate.d/kube-apiserver",
		"File//etc/logrotate.d/kube-controller-manager",
		"File//etc/logrotate.d/kube-proxy",
		"File//etc/logrotate.d/kube-scheduler",
	}
	logrotateTasks := []string{
		"File//etc/logrotate.d/docker",
		"File//etc/logrotate.d/etcd",
		"File//etc/logrotate.d/etcd-events",
		"File//etc/logrotate.d/etcd-leases",
		"File//etc/logrotate.d/kube-addons",
		"File//etc/logrotate.d/kubelet",
		"Package/logrotate",
		"Service/logrotate.service",
		"Service/logrotate.timer",
	}

	tests := []struct {
		name              string
		kubernetesVersion string
		etcdManifests     []string
		wantTasks         []string
	}{
		{
			name:              "without etcd before 1.36",
			kubernetesVersion: "1.35.0",
			wantTasks:         slices.Concat(logrotateTasks, componentFiles),
		},
		{
			name:              "without etcd from 1.36",
			kubernetesVersion: "1.36.0",
			wantTasks:         nil,
		},
		{
			name:              "with etcd from 1.36",
			kubernetesVersion: "1.36.0",
			etcdManifests:     []string{"memfs://manifests/etcd/main.yaml"},
			wantTasks:         logrotateTasks,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &LogrotateBuilder{
				NodeupModelContext: &NodeupModelContext{
					NodeupConfig:      &nodeup.Config{EtcdManifests: tc.etcdManifests},
					Distribution:      distributions.DistributionDebian13,
					kubernetesVersion: kopsmodel.MustParseKubernetesVersion(tc.kubernetesVersion),
				},
			}
			c := &fi.NodeupModelBuilderContext{Tasks: map[string]fi.NodeupTask{}}

			if err := b.Build(c); err != nil {
				t.Fatalf("Build() failed: %v", err)
			}

			got := slices.Sorted(maps.Keys(c.Tasks))
			want := slices.Sorted(slices.Values(tc.wantTasks))
			if !slices.Equal(got, want) {
				t.Errorf("tasks = %v, want %v", got, want)
			}
		})
	}
}
