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
	"reflect"
	"testing"

	kopsmodel "k8s.io/kops/pkg/apis/kops/model"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/nodeup/nodetasks"
)

func TestAddGoRunnerLogFileTasks(t *testing.T) {
	tests := []struct {
		kubernetesVersion string
		want              map[string]*nodetasks.File
	}{
		{
			kubernetesVersion: "1.35.0",
			want: map[string]*nodetasks.File{
				"File//var/log/kube-proxy.log": {
					Path:        "/var/log/kube-proxy.log",
					Contents:    fi.NewStringResource(""),
					Type:        nodetasks.FileType_File,
					Mode:        s("0400"),
					IfNotExists: true,
				},
				"File//var/log/kube-scheduler.log": {
					Path:        "/var/log/kube-scheduler.log",
					Contents:    fi.NewStringResource(""),
					Type:        nodetasks.FileType_File,
					Mode:        s("0400"),
					IfNotExists: true,
				},
			},
		},
		{
			kubernetesVersion: "1.36.0",
			want: map[string]*nodetasks.File{
				"File//var/log/kubernetes": {
					Path: "/var/log/kubernetes",
					Type: nodetasks.FileType_Directory,
					Mode: s("0755"),
				},
				"File//var/log/kube-proxy.log": {
					Path:    "/var/log/kube-proxy.log",
					Type:    nodetasks.FileType_Symlink,
					Symlink: s("kubernetes/kube-proxy.log"),
				},
				"File//var/log/kube-scheduler.log": {
					Path:    "/var/log/kube-scheduler.log",
					Type:    nodetasks.FileType_Symlink,
					Symlink: s("kubernetes/kube-scheduler.log"),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.kubernetesVersion, func(t *testing.T) {
			b := &NodeupModelContext{
				kubernetesVersion: kopsmodel.MustParseKubernetesVersion(tc.kubernetesVersion),
			}
			c := &fi.NodeupModelBuilderContext{Tasks: map[string]fi.NodeupTask{}}

			// Two components, so that both ensure the shared log directory.
			b.addGoRunnerLogFileTasks(c, "kube-proxy")
			b.addGoRunnerLogFileTasks(c, "kube-scheduler")

			got := map[string]*nodetasks.File{}
			for key, task := range c.Tasks {
				got[key] = task.(*nodetasks.File)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("tasks = %+v, want %+v", got, tc.want)
			}
		})
	}
}
