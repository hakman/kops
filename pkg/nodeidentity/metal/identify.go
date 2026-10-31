/*
Copyright 2024 The Kubernetes Authors.

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
	"context"
	"fmt"
	"maps"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kops/pkg/apis/kops"
	kopsv1alpha2 "k8s.io/kops/pkg/apis/kops/v1alpha2"
	"k8s.io/kops/pkg/apis/kops/validation"
	"k8s.io/kops/pkg/client/simple"
	"k8s.io/kops/pkg/nodeidentity"
	"k8s.io/kops/pkg/nodelabels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// nodeIdentifier identifies nodes that joined with a machine key (`kops toolbox enroll`)
// from the Host object named after the node, which records the node's instance group.
// Nodes without a Host object are passed to next, the cluster cloud's identifier.
type nodeIdentifier struct {
	hosts       client.Reader
	clientset   simple.Clientset
	clusterName string
	next        nodeidentity.Identifier
}

var _ nodeidentity.Identifier = &nodeIdentifier{}

// New creates and returns a nodeidentity.Identifier for nodes that have a Host object.
// Nodes without one are identified by next, if any.
func New(hosts client.Reader, clientset simple.Clientset, clusterName string, next nodeidentity.Identifier) nodeidentity.Identifier {
	return &nodeIdentifier{
		hosts:       hosts,
		clientset:   clientset,
		clusterName: clusterName,
		next:        next,
	}
}

// IdentifyNode returns the labels of the instance group recorded in the node's Host object.
// The Host name is bound to the node name by the machine key, so the providerID is not consulted.
func (i *nodeIdentifier) IdentifyNode(ctx context.Context, node *corev1.Node) (*nodeidentity.Info, error) {
	id := types.NamespacedName{Namespace: "kops-system", Name: node.Name}
	host := &kopsv1alpha2.Host{}
	if err := i.hosts.Get(ctx, id, host); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("error getting Host %v: %w", id, err)
		}
		if i.next == nil {
			return nil, fmt.Errorf("no Host for node %s", node.Name)
		}
		return i.next.IdentifyNode(ctx, node)
	}

	// The instance group name becomes a path in the state store.
	igName := host.Spec.InstanceGroup
	if errs := validation.ValidateInstanceGroupName(igName, field.NewPath("spec", "instanceGroup")); len(errs) > 0 {
		return nil, fmt.Errorf("invalid instance group for Host %v: %w", id, errs.ToAggregate())
	}

	cluster, err := i.clientset.GetCluster(ctx, i.clusterName)
	if err != nil {
		return nil, fmt.Errorf("error getting cluster %q: %w", i.clusterName, err)
	}
	ig, err := i.clientset.InstanceGroupsFor(cluster).Get(ctx, igName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting instance group %q for Host %v: %w", igName, id, err)
	}

	igLabels, err := nodelabels.BuildNodeLabels(cluster, ig)
	if err != nil {
		return nil, fmt.Errorf("error building labels for instance group %q: %w", igName, err)
	}
	labels := map[string]string{kops.NodeLabelInstanceGroup: ig.Name}
	maps.Copy(labels, igLabels)

	return &nodeidentity.Info{Labels: labels}, nil
}
