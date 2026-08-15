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

// Package slimclient provides typed Kubernetes clients for a small, explicit
// set of API groups.
//
// The generated kubernetes.Clientset, and anything else that imports
// k8s.io/client-go/kubernetes/scheme (including the per-group typed clients
// and the discovery client), registers every k8s.io/api group in its scheme.
// That registration makes the generated marshalling code for all API groups
// reachable, adding several MB to every binary that links it. Building the
// scheme and REST clients here keeps only the API groups a component actually
// uses reachable.
//
// The interfaces intentionally expose only the operations kOps components
// use; extend them as needed.
package slimclient

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/gentype"
	"k8s.io/client-go/rest"
)

var (
	scheme         = runtime.NewScheme()
	codecs         = serializer.NewCodecFactory(scheme)
	parameterCodec = runtime.NewParameterCodec(scheme)
)

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(networkingv1.AddToScheme(scheme))
}

// Interface provides typed access to the API groups registered in this
// package. It is implemented by Clientset; tests can substitute a fake.
type Interface interface {
	CoreV1() CoreV1Interface
	NetworkingV1() NetworkingV1Interface
}

// CoreV1Interface provides typed access to core/v1 resources.
type CoreV1Interface interface {
	Pods(namespace string) PodInterface
	Services(namespace string) ServiceInterface
	Nodes() NodeInterface
}

// NetworkingV1Interface provides typed access to networking.k8s.io/v1 resources.
type NetworkingV1Interface interface {
	Ingresses(namespace string) IngressInterface
}

// PodInterface has the operations kOps uses on core/v1 Pods.
type PodInterface interface {
	List(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// ServiceInterface has the operations kOps uses on core/v1 Services.
type ServiceInterface interface {
	List(ctx context.Context, opts metav1.ListOptions) (*corev1.ServiceList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// NodeInterface has the operations kOps uses on core/v1 Nodes.
type NodeInterface interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Node, error)
	List(ctx context.Context, opts metav1.ListOptions) (*corev1.NodeList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// IngressInterface has the operations kOps uses on networking.k8s.io/v1 Ingresses.
type IngressInterface interface {
	List(ctx context.Context, opts metav1.ListOptions) (*networkingv1.IngressList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

// Clientset implements Interface against a real API server.
type Clientset struct {
	corev1       *coreV1Client
	networkingv1 *networkingV1Client
}

var _ Interface = &Clientset{}

// NewForConfig returns a Clientset for the given config.
func NewForConfig(config *rest.Config) (*Clientset, error) {
	coreClient, err := restClientFor(config, schema.GroupVersion{Version: "v1"}, "/api")
	if err != nil {
		return nil, err
	}
	networkingClient, err := restClientFor(config, networkingv1.SchemeGroupVersion, "/apis")
	if err != nil {
		return nil, err
	}
	return &Clientset{
		corev1:       &coreV1Client{client: coreClient},
		networkingv1: &networkingV1Client{client: networkingClient},
	}, nil
}

func restClientFor(config *rest.Config, gv schema.GroupVersion, apiPath string) (rest.Interface, error) {
	c := rest.CopyConfig(config)
	c.GroupVersion = &gv
	c.APIPath = apiPath
	c.NegotiatedSerializer = codecs.WithoutConversion()
	if c.UserAgent == "" {
		c.UserAgent = rest.DefaultKubernetesUserAgent()
	}
	return rest.RESTClientFor(c)
}

// CoreV1 returns the client for the core/v1 API group.
func (c *Clientset) CoreV1() CoreV1Interface {
	return c.corev1
}

// NetworkingV1 returns the client for the networking.k8s.io/v1 API group.
func (c *Clientset) NetworkingV1() NetworkingV1Interface {
	return c.networkingv1
}

type coreV1Client struct {
	client rest.Interface
}

func (c *coreV1Client) Pods(namespace string) PodInterface {
	return gentype.NewClientWithList[*corev1.Pod, *corev1.PodList](
		"pods", c.client, parameterCodec, namespace,
		func() *corev1.Pod { return &corev1.Pod{} },
		func() *corev1.PodList { return &corev1.PodList{} })
}

func (c *coreV1Client) Services(namespace string) ServiceInterface {
	return gentype.NewClientWithList[*corev1.Service, *corev1.ServiceList](
		"services", c.client, parameterCodec, namespace,
		func() *corev1.Service { return &corev1.Service{} },
		func() *corev1.ServiceList { return &corev1.ServiceList{} })
}

func (c *coreV1Client) Nodes() NodeInterface {
	return gentype.NewClientWithList[*corev1.Node, *corev1.NodeList](
		"nodes", c.client, parameterCodec, "",
		func() *corev1.Node { return &corev1.Node{} },
		func() *corev1.NodeList { return &corev1.NodeList{} })
}

type networkingV1Client struct {
	client rest.Interface
}

func (c *networkingV1Client) Ingresses(namespace string) IngressInterface {
	return gentype.NewClientWithList[*networkingv1.Ingress, *networkingv1.IngressList](
		"ingresses", c.client, parameterCodec, namespace,
		func() *networkingv1.Ingress { return &networkingv1.Ingress{} },
		func() *networkingv1.IngressList { return &networkingv1.IngressList{} })
}
