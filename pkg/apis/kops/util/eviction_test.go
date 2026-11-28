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

package util

import (
	"reflect"
	"testing"
)

func TestAllocatableEvictionThresholds(t *testing.T) {
	grid := []struct {
		name         string
		evictionHard string
		want         map[string]string
		wantErr      bool
	}{
		{
			name: "empty",
		},
		{
			name:         "other signals are left out",
			evictionHard: "memory.available<100Mi,nodefs.available<10%,nodefs.inodesFree<5%,imagefs.available<10%,imagefs.inodesFree<5%",
			want: map[string]string{
				"memory.available": "100Mi",
				"nodefs.available": "10%",
			},
		},
		{
			name:         "only other signals",
			evictionHard: "imagefs.available<10%,pid.available<5%",
		},
		{
			name:         "spaces are trimmed",
			evictionHard: " memory.available < 100Mi , nodefs.available<10% ",
			want: map[string]string{
				"memory.available": "100Mi",
				"nodefs.available": "10%",
			},
		},
		{
			name:         "last value wins for a repeated signal",
			evictionHard: "memory.available<100Mi,memory.available<200Mi",
			want:         map[string]string{"memory.available": "200Mi"},
		},
		{
			name:         "empty value is kept",
			evictionHard: "memory.available<",
			want:         map[string]string{"memory.available": ""},
		},
		{
			name:         "missing separator",
			evictionHard: "memory.available",
			wantErr:      true,
		},
		{
			name:         "missing separator on another signal",
			evictionHard: "memory.available<100Mi,pid.available",
			wantErr:      true,
		},
		{
			name:         "trailing comma",
			evictionHard: "memory.available<100Mi,",
			wantErr:      true,
		},
		{
			name:         "wrong operator",
			evictionHard: "memory.available>100Mi",
			wantErr:      true,
		},
	}

	for _, g := range grid {
		t.Run(g.name, func(t *testing.T) {
			got, err := AllocatableEvictionThresholds(g.evictionHard)
			if (err != nil) != g.wantErr {
				t.Fatalf("AllocatableEvictionThresholds() error = %v, wantErr %v", err, g.wantErr)
			}
			if !reflect.DeepEqual(got, g.want) {
				t.Errorf("AllocatableEvictionThresholds() = %v, want %v", got, g.want)
			}
		})
	}
}
