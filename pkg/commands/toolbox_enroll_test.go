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

package commands

import (
	"strings"
	"testing"
)

// TestRewriteChannelsManifestForEnroll guards the regression where the
// kops-channels static pod still pointed at the remote VFS bootstrap URL on
// enrolled nodes.
func TestRewriteChannelsManifestForEnroll(t *testing.T) {
	in := []byte(`apiVersion: v1
kind: Pod
metadata:
  name: kops-channels
spec:
  containers:
  - name: kops-channels
    args:
    - apply
    - channel
    - --yes
    - s3://example/clusters/my-cluster/addons/bootstrap-channel.yaml
    - s3://example/clusters/my-cluster/addons/custom.yaml
`)

	out, err := rewriteChannelsManifestForEnroll(
		in,
		"s3://example/clusters/my-cluster/addons/bootstrap-channel.yaml",
		"/etc/kubernetes/kops/config/addons",
	)
	if err != nil {
		t.Fatalf("rewriteChannelsManifestForEnroll: %v", err)
	}

	s := string(out)
	if strings.Contains(s, "s3://example/clusters/my-cluster/addons/bootstrap-channel.yaml") {
		t.Errorf("bootstrap URL not rewritten:\n%s", s)
	}
	if !strings.Contains(s, "file:///etc/kubernetes/kops/config/addons/bootstrap-channel.yaml") {
		t.Errorf("expected local file:// bootstrap URL in args:\n%s", s)
	}
	if !strings.Contains(s, "s3://example/clusters/my-cluster/addons/custom.yaml") {
		t.Errorf("non-bootstrap channel URL should not be rewritten:\n%s", s)
	}
}
