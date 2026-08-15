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
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	apidiscoveryv2 "k8s.io/api/apidiscovery/v2"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// acceptDiscovery prefers the aggregated discovery formats, falling back to
// the legacy per-group format on older servers.
const acceptDiscovery = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList," +
	"application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList," +
	"application/json"

// restMapper is a meta.RESTMapper backed by API server discovery, fetched
// lazily and refreshed when a mapping is not found. It replaces
// restmapper.DeferredDiscoveryRESTMapper, whose discovery client links the
// full k8s.io/client-go/kubernetes/scheme.
type restMapper struct {
	client rest.Interface

	mu       sync.Mutex
	delegate *meta.DefaultRESTMapper
}

var _ meta.RESTMapper = &restMapper{}

// NewRESTMapper returns a meta.RESTMapper backed by API server discovery.
func NewRESTMapper(config *rest.Config) (meta.RESTMapper, error) {
	restClient, err := restClientFor(config, schema.GroupVersion{Version: "v1"}, "/api")
	if err != nil {
		return nil, err
	}
	return &restMapper{client: restClient}, nil
}

func (m *restMapper) getDelegate(ctx context.Context) (*meta.DefaultRESTMapper, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.delegate == nil {
		delegate, err := m.discover(ctx)
		if err != nil {
			return nil, err
		}
		m.delegate = delegate
	}
	return m.delegate, nil
}

// refresh re-runs discovery; called when a mapping is not found, e.g. after a
// CRD has been applied earlier in the same run.
func (m *restMapper) refresh(ctx context.Context) (*meta.DefaultRESTMapper, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delegate, err := m.discover(ctx)
	if err != nil {
		return nil, err
	}
	m.delegate = delegate
	return m.delegate, nil
}

type discoveredResource struct {
	gvk      schema.GroupVersionKind
	plural   schema.GroupVersionResource
	singular schema.GroupVersionResource
	scope    meta.RESTScope
}

func (m *restMapper) discover(ctx context.Context) (*meta.DefaultRESTMapper, error) {
	var resources []discoveredResource
	var groupVersions []schema.GroupVersion
	for _, path := range []string{"/api", "/apis"} {
		pathResources, pathGroupVersions, err := m.discoverPath(ctx, path)
		if err != nil {
			return nil, err
		}
		resources = append(resources, pathResources...)
		groupVersions = append(groupVersions, pathGroupVersions...)
	}

	delegate := meta.NewDefaultRESTMapper(groupVersions)
	for _, r := range resources {
		delegate.AddSpecific(r.gvk, r.plural, r.singular, r.scope)
	}
	return delegate, nil
}

func (m *restMapper) discoverPath(ctx context.Context, path string) ([]discoveredResource, []schema.GroupVersion, error) {
	body, err := m.client.Get().AbsPath(path).SetHeader("Accept", acceptDiscovery).Do(ctx).Raw()
	if err != nil {
		return nil, nil, fmt.Errorf("fetching discovery information from %s: %w", path, err)
	}

	var typeMeta metav1.TypeMeta
	if err := json.Unmarshal(body, &typeMeta); err != nil {
		return nil, nil, fmt.Errorf("parsing discovery response from %s: %w", path, err)
	}

	switch typeMeta.Kind {
	case "APIGroupDiscoveryList":
		// The v2beta1 and v2 wire formats are identical.
		var groupList apidiscoveryv2.APIGroupDiscoveryList
		if err := json.Unmarshal(body, &groupList); err != nil {
			return nil, nil, fmt.Errorf("parsing aggregated discovery response from %s: %w", path, err)
		}
		return parseAggregatedDiscovery(&groupList)

	case "APIVersions":
		// Legacy core group discovery.
		var apiVersions metav1.APIVersions
		if err := json.Unmarshal(body, &apiVersions); err != nil {
			return nil, nil, fmt.Errorf("parsing legacy discovery response from %s: %w", path, err)
		}
		return m.discoverLegacyGroupVersions(ctx, path, apiVersions.Versions)

	case "APIGroupList":
		// Legacy grouped discovery.
		var groupList metav1.APIGroupList
		if err := json.Unmarshal(body, &groupList); err != nil {
			return nil, nil, fmt.Errorf("parsing legacy discovery response from %s: %w", path, err)
		}
		var groupVersions []string
		for _, group := range groupList.Groups {
			for _, gv := range group.Versions {
				groupVersions = append(groupVersions, gv.GroupVersion)
			}
		}
		return m.discoverLegacyGroupVersions(ctx, path, groupVersions)

	default:
		return nil, nil, fmt.Errorf("unexpected discovery response kind %q from %s", typeMeta.Kind, path)
	}
}

func parseAggregatedDiscovery(groupList *apidiscoveryv2.APIGroupDiscoveryList) ([]discoveredResource, []schema.GroupVersion, error) {
	var resources []discoveredResource
	var groupVersions []schema.GroupVersion
	for _, group := range groupList.Items {
		for i, version := range group.Versions {
			gv := schema.GroupVersion{Group: group.Name, Version: version.Version}
			if i == 0 {
				// Versions are listed in order of preference.
				groupVersions = append(groupVersions, gv)
			}
			for _, resource := range version.Resources {
				if resource.ResponseKind == nil || resource.ResponseKind.Kind == "" {
					continue
				}
				scope := meta.RESTScopeRoot
				if resource.Scope == apidiscoveryv2.ScopeNamespace {
					scope = meta.RESTScopeNamespace
				}
				singular := resource.SingularResource
				if singular == "" {
					singular = resource.Resource
				}
				resources = append(resources, discoveredResource{
					gvk:      gv.WithKind(resource.ResponseKind.Kind),
					plural:   gv.WithResource(resource.Resource),
					singular: gv.WithResource(singular),
					scope:    scope,
				})
			}
		}
	}
	return resources, groupVersions, nil
}

func (m *restMapper) discoverLegacyGroupVersions(ctx context.Context, path string, groupVersionNames []string) ([]discoveredResource, []schema.GroupVersion, error) {
	var resources []discoveredResource
	var groupVersions []schema.GroupVersion
	for _, gvName := range groupVersionNames {
		gv, err := schema.ParseGroupVersion(gvName)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing group version %q: %w", gvName, err)
		}
		groupVersions = append(groupVersions, gv)

		body, err := m.client.Get().AbsPath(path + "/" + gvName).Do(ctx).Raw()
		if err != nil {
			return nil, nil, fmt.Errorf("fetching discovery information from %s/%s: %w", path, gvName, err)
		}
		var resourceList metav1.APIResourceList
		if err := json.Unmarshal(body, &resourceList); err != nil {
			return nil, nil, fmt.Errorf("parsing discovery response from %s/%s: %w", path, gvName, err)
		}
		for _, resource := range resourceList.APIResources {
			if strings.Contains(resource.Name, "/") {
				// Skip subresources.
				continue
			}
			scope := meta.RESTScopeRoot
			if resource.Namespaced {
				scope = meta.RESTScopeNamespace
			}
			singular := resource.SingularName
			if singular == "" {
				singular = resource.Name
			}
			resources = append(resources, discoveredResource{
				gvk:      gv.WithKind(resource.Kind),
				plural:   gv.WithResource(resource.Name),
				singular: gv.WithResource(singular),
				scope:    scope,
			})
		}
	}
	return resources, groupVersions, nil
}

func (m *restMapper) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	ctx := context.Background()
	delegate, err := m.getDelegate(ctx)
	if err != nil {
		return nil, err
	}
	mapping, err := delegate.RESTMapping(gk, versions...)
	if meta.IsNoMatchError(err) {
		if delegate, refreshErr := m.refresh(ctx); refreshErr == nil {
			mapping, err = delegate.RESTMapping(gk, versions...)
		}
	}
	return mapping, err
}

func (m *restMapper) RESTMappings(gk schema.GroupKind, versions ...string) ([]*meta.RESTMapping, error) {
	ctx := context.Background()
	delegate, err := m.getDelegate(ctx)
	if err != nil {
		return nil, err
	}
	mappings, err := delegate.RESTMappings(gk, versions...)
	if meta.IsNoMatchError(err) {
		if delegate, refreshErr := m.refresh(ctx); refreshErr == nil {
			mappings, err = delegate.RESTMappings(gk, versions...)
		}
	}
	return mappings, err
}

func (m *restMapper) KindFor(resource schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	delegate, err := m.getDelegate(context.Background())
	if err != nil {
		return schema.GroupVersionKind{}, err
	}
	return delegate.KindFor(resource)
}

func (m *restMapper) KindsFor(resource schema.GroupVersionResource) ([]schema.GroupVersionKind, error) {
	delegate, err := m.getDelegate(context.Background())
	if err != nil {
		return nil, err
	}
	return delegate.KindsFor(resource)
}

func (m *restMapper) ResourceFor(input schema.GroupVersionResource) (schema.GroupVersionResource, error) {
	delegate, err := m.getDelegate(context.Background())
	if err != nil {
		return schema.GroupVersionResource{}, err
	}
	return delegate.ResourceFor(input)
}

func (m *restMapper) ResourcesFor(input schema.GroupVersionResource) ([]schema.GroupVersionResource, error) {
	delegate, err := m.getDelegate(context.Background())
	if err != nil {
		return nil, err
	}
	return delegate.ResourcesFor(input)
}

func (m *restMapper) ResourceSingularizer(resource string) (string, error) {
	delegate, err := m.getDelegate(context.Background())
	if err != nil {
		return "", err
	}
	return delegate.ResourceSingularizer(resource)
}
