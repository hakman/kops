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

// Package fake adapts the generated fake clientset to slimclient.Interface
// for use in tests. It must not be imported from non-test code: it links the
// full generated clientset, which is exactly what slimclient avoids.
package fake

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes/fake"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	typednetworkingv1 "k8s.io/client-go/kubernetes/typed/networking/v1"
	"k8s.io/kops/pkg/slimclient"
)

// Clientset implements slimclient.Interface backed by a fake clientset.
type Clientset struct {
	// Fake is the underlying fake clientset, for seeding and inspecting
	// objects with the full generated API.
	Fake *fake.Clientset
}

var _ slimclient.Interface = &Clientset{}

// NewClientset returns a fake slimclient seeded with the given objects.
func NewClientset(objects ...runtime.Object) *Clientset {
	return &Clientset{Fake: fake.NewClientset(objects...)}
}

func (c *Clientset) CoreV1() slimclient.CoreV1Interface {
	return &coreV1{client: c.Fake.CoreV1()}
}

func (c *Clientset) NetworkingV1() slimclient.NetworkingV1Interface {
	return &networkingV1{client: c.Fake.NetworkingV1()}
}

func (c *Clientset) ServerVersion(ctx context.Context) (*version.Info, error) {
	return c.Fake.Discovery().ServerVersion()
}

type coreV1 struct {
	client typedcorev1.CoreV1Interface
}

func (c *coreV1) Namespaces() slimclient.NamespaceInterface {
	return c.client.Namespaces()
}

func (c *coreV1) Nodes() slimclient.NodeInterface {
	return c.client.Nodes()
}

func (c *coreV1) Pods(namespace string) slimclient.PodInterface {
	return c.client.Pods(namespace)
}

func (c *coreV1) Secrets(namespace string) slimclient.SecretInterface {
	return c.client.Secrets(namespace)
}

func (c *coreV1) Services(namespace string) slimclient.ServiceInterface {
	return c.client.Services(namespace)
}

type networkingV1 struct {
	client typednetworkingv1.NetworkingV1Interface
}

func (c *networkingV1) Ingresses(namespace string) slimclient.IngressInterface {
	return c.client.Ingresses(namespace)
}
