/*
Copyright The Kubernetes Authors.

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

package metal

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kops/cmd/kops-controller/pkg/controllerclientset"
	kopsv1alpha2 "k8s.io/kops/pkg/apis/kops/v1alpha2"
	"k8s.io/kops/pkg/nodeidentity"
	"k8s.io/kops/util/pkg/vfs"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// nextIdentifier records the nodes passed on to it.
type nextIdentifier struct {
	nodes []string
}

func (i *nextIdentifier) IdentifyNode(_ context.Context, node *corev1.Node) (*nodeidentity.Info, error) {
	i.nodes = append(i.nodes, node.Name)
	return &nodeidentity.Info{InstanceID: node.Spec.ProviderID}, nil
}

// fakeHosts is a client.Reader that serves the Host objects it holds, by name.
type fakeHosts map[string]*kopsv1alpha2.Host

func (f fakeHosts) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	host, found := f[key.Name]
	if !found || key.Namespace != "kops-system" {
		return apierrors.NewNotFound(schema.GroupResource{Group: "kops.k8s.io", Resource: "hosts"}, key.Name)
	}
	host.DeepCopyInto(obj.(*kopsv1alpha2.Host))
	return nil
}

func (f fakeHosts) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return fmt.Errorf("not implemented")
}

const clusterName = "hybrid.example.com"

var stateStore = map[string]string{
	"config": `
apiVersion: kops.k8s.io/v1alpha2
kind: Cluster
metadata:
  name: hybrid.example.com
spec:
  kubelet:
    nodeLabels:
      cluster-label: from-cluster
`,
	"instancegroup/nodes-gpu": `
apiVersion: kops.k8s.io/v1alpha2
kind: InstanceGroup
metadata:
  name: nodes-gpu
spec:
  role: Node
  nodeLabels:
    gpu: "true"
`,
}

func newHost(name, instanceGroup string) *kopsv1alpha2.Host {
	host := &kopsv1alpha2.Host{}
	host.Namespace = "kops-system"
	host.Name = name
	host.Spec.InstanceGroup = instanceGroup
	return host
}

func TestIdentifyNode(t *testing.T) {
	ctx := t.Context()

	vfsContext := vfs.NewVFSContext()
	vfsContext.ResetMemfsContext(true)
	configBase, err := vfsContext.BuildVfsPath("memfs://state/" + clusterName)
	if err != nil {
		t.Fatalf("building config base: %v", err)
	}
	for name, contents := range stateStore {
		if err := configBase.Join(name).WriteFile(ctx, bytes.NewReader([]byte(contents)), nil); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	clientset, err := controllerclientset.New(vfsContext, configBase, clusterName, nil, nil)
	if err != nil {
		t.Fatalf("building clientset: %v", err)
	}

	hosts := fakeHosts{
		"gpu-1": newHost("gpu-1", "nodes-gpu"),
		"gpu-2": newHost("gpu-2", "nodes-missing"),
	}
	next := &nextIdentifier{}
	identifier := New(hosts, clientset, clusterName, next)

	// The providerID names a cloud instance; the Host object decides regardless.
	node := &corev1.Node{}
	node.Name = "gpu-1"
	node.Spec.ProviderID = "gce://project/zone/control-plane-instance"
	info, err := identifier.IdentifyNode(ctx, node)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := map[string]string{
		"cluster-label":                "from-cluster",
		"gpu":                          "true",
		"kops.k8s.io/instancegroup":    "nodes-gpu",
		"node-role.kubernetes.io/node": "",
	}
	if !reflect.DeepEqual(info.Labels, expected) {
		t.Errorf("expected labels %v, got %v", expected, info.Labels)
	}

	node.Name = "nodes-1"
	info, err = identifier.IdentifyNode(ctx, node)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.InstanceID != node.Spec.ProviderID || !reflect.DeepEqual(next.nodes, []string{"nodes-1"}) {
		t.Errorf("expected a node without a Host to be passed to next, got %v (next saw %v)", info, next.nodes)
	}

	node.Name = "gpu-2"
	if _, err := identifier.IdentifyNode(ctx, node); err == nil {
		t.Error("expected an error for a Host with an unknown instance group")
	}

	node.Name = "nodes-1"
	if _, err := New(hosts, clientset, clusterName, nil).IdentifyNode(ctx, node); err == nil {
		t.Error("expected an error for a node without a Host when there is no next identifier")
	}
	if len(next.nodes) != 1 {
		t.Errorf("expected next not to be consulted for a Host with an unknown instance group, got %v", next.nodes)
	}
}
