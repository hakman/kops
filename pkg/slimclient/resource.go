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

package slimclient

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
)

// resourceClient implements the typed resource operations on top of a
// rest.Interface, the way generated clients did before client-go 1.31.
// client-go's gentype package provides the same thing, but its fake.go pulls
// k8s.io/client-go/testing and its transitive dependencies (managed fields,
// strategic merge patch, OpenAPI) into production binaries.
type resourceClient[T runtime.Object, L runtime.Object] struct {
	client    rest.Interface
	resource  string
	namespace string // empty for cluster-scoped resources
	newObject func() T
	newList   func() L
}

func timeoutFor(opts metav1.ListOptions) time.Duration {
	if opts.TimeoutSeconds != nil {
		return time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	return 0
}

func (c *resourceClient[T, L]) Get(ctx context.Context, name string, opts metav1.GetOptions) (T, error) {
	result := c.newObject()
	err := c.client.Get().
		NamespaceIfScoped(c.namespace, c.namespace != "").
		Resource(c.resource).
		Name(name).
		VersionedParams(&opts, parameterCodec).
		Do(ctx).
		Into(result)
	return result, err
}

func (c *resourceClient[T, L]) List(ctx context.Context, opts metav1.ListOptions) (L, error) {
	result := c.newList()
	err := c.client.Get().
		NamespaceIfScoped(c.namespace, c.namespace != "").
		Resource(c.resource).
		VersionedParams(&opts, parameterCodec).
		Timeout(timeoutFor(opts)).
		Do(ctx).
		Into(result)
	return result, err
}

func (c *resourceClient[T, L]) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		NamespaceIfScoped(c.namespace, c.namespace != "").
		Resource(c.resource).
		VersionedParams(&opts, parameterCodec).
		Timeout(timeoutFor(opts)).
		Watch(ctx)
}

func (c *resourceClient[T, L]) Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error) {
	result := c.newObject()
	err := c.client.Post().
		NamespaceIfScoped(c.namespace, c.namespace != "").
		Resource(c.resource).
		VersionedParams(&opts, parameterCodec).
		Body(obj).
		Do(ctx).
		Into(result)
	return result, err
}

func (c *resourceClient[T, L]) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (T, error) {
	result := c.newObject()
	err := c.client.Patch(pt).
		NamespaceIfScoped(c.namespace, c.namespace != "").
		Resource(c.resource).
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, parameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return result, err
}
