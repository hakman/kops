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

package kops

import "testing"

func TestKopsBaseURLFromMarker(t *testing.T) {
	for _, tc := range []struct {
		name      string
		markerURL string
		contents  string
		want      string
		wantErr   bool
	}{
		{
			name:      "version-only marker",
			markerURL: "https://storage.googleapis.com/k8s-staging-kops/kops/releases/latest.txt",
			contents:  "1.37.0-beta.2+abc123\n",
			want:      "https://storage.googleapis.com/k8s-staging-kops/kops/releases/1.37.0-beta.2+abc123",
		},
		{
			name:      "version-only marker served by dl.k8s.io",
			markerURL: "https://dl.k8s.io/ci/kops/latest-1.34.txt",
			contents:  "1.34.2+abc123",
			want:      "https://dl.k8s.io/ci/kops/1.34.2+abc123",
		},
		{
			name:      "version-only marker with query string",
			markerURL: "https://storage.googleapis.com/k8s-staging-kops/kops/releases/latest.txt?mirror=a/b",
			contents:  "1.37.0-beta.2+abc123",
			want:      "https://storage.googleapis.com/k8s-staging-kops/kops/releases/1.37.0-beta.2+abc123",
		},
		{
			name:      "legacy marker with full URL",
			markerURL: "https://storage.googleapis.com/k8s-staging-kops/kops/releases/markers/master/latest-ci.txt",
			contents:  "https://storage.googleapis.com/k8s-staging-kops/kops/releases/1.37.0-beta.2+abc123\n",
			want:      "https://storage.googleapis.com/k8s-staging-kops/kops/releases/1.37.0-beta.2+abc123",
		},
		{
			name:      "legacy marker with local file URL",
			markerURL: "file:///tmp/latest-ci.txt",
			contents:  "file:///tmp/kops/1.37.0-beta.2+abc123",
			want:      "file:///tmp/kops/1.37.0-beta.2+abc123",
		},
		{
			name:      "empty marker",
			markerURL: "https://storage.googleapis.com/k8s-staging-kops/kops/releases/latest.txt",
			contents:  "\n",
			wantErr:   true,
		},
		{
			name:      "marker with a path instead of a version",
			markerURL: "https://storage.googleapis.com/k8s-staging-kops/kops/releases/latest.txt",
			contents:  "kops/releases/1.37.0-beta.2+abc123",
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kopsBaseURLFromMarker(tc.markerURL, tc.contents)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
