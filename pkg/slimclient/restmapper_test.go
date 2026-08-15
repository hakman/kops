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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// aggregatedAPI is the shape of a real "GET /api" response from an aggregated
// discovery capable API server (apidiscovery.k8s.io/v2, GA since 1.30).
const aggregatedAPI = `{
	"kind": "APIGroupDiscoveryList",
	"apiVersion": "apidiscovery.k8s.io/v2",
	"metadata": {},
	"items": [
		{
			"metadata": {"name": ""},
			"versions": [
				{
					"version": "v1",
					"resources": [
						{"resource": "pods", "responseKind": {"group": "", "version": "v1", "kind": "Pod"}, "scope": "Namespaced", "singularResource": "pod", "verbs": ["get", "list", "watch"], "subresources": [{"subresource": "status", "responseKind": {"group": "", "version": "v1", "kind": "Pod"}, "verbs": ["get"]}]},
						{"resource": "services", "responseKind": {"group": "", "version": "v1", "kind": "Service"}, "scope": "Namespaced", "singularResource": "service", "verbs": ["get", "list", "watch"]},
						{"resource": "nodes", "responseKind": {"group": "", "version": "v1", "kind": "Node"}, "scope": "Cluster", "singularResource": "node", "verbs": ["get", "list", "watch"]}
					]
				}
			]
		}
	]
}`

const aggregatedAPIs = `{
	"kind": "APIGroupDiscoveryList",
	"apiVersion": "apidiscovery.k8s.io/v2",
	"metadata": {},
	"items": [
		{
			"metadata": {"name": "apps"},
			"versions": [
				{
					"version": "v1",
					"resources": [
						{"resource": "deployments", "responseKind": {"group": "apps", "version": "v1", "kind": "Deployment"}, "scope": "Namespaced", "singularResource": "deployment", "verbs": ["get", "list", "watch"]}
					]
				}
			]
		},
		{
			"metadata": {"name": "networking.k8s.io"},
			"versions": [
				{
					"version": "v1",
					"resources": [
						{"resource": "ingresses", "responseKind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"}, "scope": "Namespaced", "singularResource": "ingress", "verbs": ["get", "list", "watch"]}
					]
				}
			]
		}
	]
}`

// aggregatedAPIsWithCRD is aggregatedAPIs plus a CRD group, as served after a
// CRD has been applied.
const aggregatedAPIsWithCRD = `{
	"kind": "APIGroupDiscoveryList",
	"apiVersion": "apidiscovery.k8s.io/v2",
	"metadata": {},
	"items": [
		{
			"metadata": {"name": "cert-manager.io"},
			"versions": [
				{
					"version": "v1",
					"resources": [
						{"resource": "issuers", "responseKind": {"group": "cert-manager.io", "version": "v1", "kind": "Issuer"}, "scope": "Namespaced", "singularResource": "issuer", "verbs": ["get", "list", "watch"]},
						{"resource": "clusterissuers", "responseKind": {"group": "cert-manager.io", "version": "v1", "kind": "ClusterIssuer"}, "scope": "Cluster", "singularResource": "clusterissuer", "verbs": ["get", "list", "watch"]}
					]
				}
			]
		},
		{
			"metadata": {"name": "apps"},
			"versions": [
				{
					"version": "v1",
					"resources": [
						{"resource": "deployments", "responseKind": {"group": "apps", "version": "v1", "kind": "Deployment"}, "scope": "Namespaced", "singularResource": "deployment", "verbs": ["get", "list", "watch"]}
					]
				}
			]
		}
	]
}`

// Legacy discovery responses, as served by API servers without aggregated
// discovery. The client asks for the aggregated content type, and the server
// ignores the params and responds with the legacy object.
const (
	legacyAPI      = `{"kind": "APIVersions", "versions": ["v1"], "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.0.0.1:443"}]}`
	legacyAPIV1    = `{"kind": "APIResourceList", "groupVersion": "v1", "resources": [{"name": "pods", "singularName": "pod", "namespaced": true, "kind": "Pod", "verbs": ["get", "list", "watch"]}, {"name": "pods/status", "singularName": "", "namespaced": true, "kind": "Pod", "verbs": ["get"]}, {"name": "nodes", "singularName": "node", "namespaced": false, "kind": "Node", "verbs": ["get", "list", "watch"]}]}`
	legacyAPIs     = `{"kind": "APIGroupList", "apiVersion": "v1", "groups": [{"name": "apps", "versions": [{"groupVersion": "apps/v1", "version": "v1"}], "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"}}]}`
	legacyAppsV1   = `{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "apps/v1", "resources": [{"name": "deployments", "singularName": "deployment", "namespaced": true, "kind": "Deployment", "verbs": ["get", "list", "watch"]}, {"name": "deployments/scale", "singularName": "", "namespaced": true, "kind": "Scale", "verbs": ["get", "update"]}]}`
	legacyNotFound = `{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404}`
)

func newTestMapper(t *testing.T, handler http.Handler) meta.RESTMapper {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	mapper, err := NewRESTMapper(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("NewRESTMapper: %v", err)
	}
	return mapper
}

func serveJSON(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("writing response: %v", err)
	}
}

func TestRESTMapperAggregatedDiscovery(t *testing.T) {
	mapper := newTestMapper(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "apidiscovery.k8s.io") {
			t.Errorf("expected aggregated discovery accept header, got %q", r.Header.Get("Accept"))
		}
		switch r.URL.Path {
		case "/api":
			serveJSON(t, w, aggregatedAPI)
		case "/apis":
			serveJSON(t, w, aggregatedAPIs)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	grid := []struct {
		gk         schema.GroupKind
		version    string
		resource   string
		namespaced bool
	}{
		{schema.GroupKind{Kind: "Pod"}, "v1", "pods", true},
		{schema.GroupKind{Kind: "Service"}, "v1", "services", true},
		{schema.GroupKind{Kind: "Node"}, "v1", "nodes", false},
		{schema.GroupKind{Group: "apps", Kind: "Deployment"}, "v1", "deployments", true},
		{schema.GroupKind{Group: "networking.k8s.io", Kind: "Ingress"}, "v1", "ingresses", true},
	}
	for _, g := range grid {
		mapping, err := mapper.RESTMapping(g.gk, g.version)
		if err != nil {
			t.Errorf("RESTMapping(%v): %v", g.gk, err)
			continue
		}
		if mapping.Resource.Resource != g.resource {
			t.Errorf("RESTMapping(%v): got resource %q, want %q", g.gk, mapping.Resource.Resource, g.resource)
		}
		if namespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace; namespaced != g.namespaced {
			t.Errorf("RESTMapping(%v): got namespaced=%v, want %v", g.gk, namespaced, g.namespaced)
		}
	}

	// The Pod status subresource must not be registered as a resource.
	if _, err := mapper.RESTMapping(schema.GroupKind{Kind: "Pod/status"}); err == nil {
		t.Errorf("expected no mapping for subresource")
	}
}

func TestRESTMapperLegacyDiscovery(t *testing.T) {
	mapper := newTestMapper(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			serveJSON(t, w, legacyAPI)
		case "/api/v1":
			serveJSON(t, w, legacyAPIV1)
		case "/apis":
			serveJSON(t, w, legacyAPIs)
		case "/apis/apps/v1":
			serveJSON(t, w, legacyAppsV1)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	for _, g := range []struct {
		gk         schema.GroupKind
		resource   string
		namespaced bool
	}{
		{schema.GroupKind{Kind: "Pod"}, "pods", true},
		{schema.GroupKind{Kind: "Node"}, "nodes", false},
		{schema.GroupKind{Group: "apps", Kind: "Deployment"}, "deployments", true},
	} {
		mapping, err := mapper.RESTMapping(g.gk, "v1")
		if err != nil {
			t.Errorf("RESTMapping(%v): %v", g.gk, err)
			continue
		}
		if mapping.Resource.Resource != g.resource {
			t.Errorf("RESTMapping(%v): got resource %q, want %q", g.gk, mapping.Resource.Resource, g.resource)
		}
		if namespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace; namespaced != g.namespaced {
			t.Errorf("RESTMapping(%v): got namespaced=%v, want %v", g.gk, namespaced, g.namespaced)
		}
	}

	// The deployments/scale subresource must be skipped.
	if _, err := mapper.RESTMapping(schema.GroupKind{Group: "apps", Kind: "Scale"}, "v1"); err == nil {
		t.Errorf("expected no mapping for subresource kind")
	}
}

func TestRESTMapperRefreshOnMiss(t *testing.T) {
	// The first discovery response does not include the cert-manager.io
	// group; later responses do, modelling a CRD applied mid-run.
	var fetches atomic.Int32
	mapper := newTestMapper(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			serveJSON(t, w, aggregatedAPI)
		case "/apis":
			if fetches.Add(1) == 1 {
				serveJSON(t, w, aggregatedAPIs)
			} else {
				serveJSON(t, w, aggregatedAPIsWithCRD)
			}
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	issuerGK := schema.GroupKind{Group: "cert-manager.io", Kind: "Issuer"}

	// Warm the mapper with the initial discovery data.
	if _, err := mapper.RESTMapping(schema.GroupKind{Group: "apps", Kind: "Deployment"}, "v1"); err != nil {
		t.Fatalf("RESTMapping(Deployment): %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("expected 1 discovery fetch, got %d", got)
	}

	// The CRD group is not in the cached data; the mapper must refresh and
	// find it.
	mapping, err := mapper.RESTMapping(issuerGK, "v1")
	if err != nil {
		t.Fatalf("RESTMapping(Issuer) after refresh: %v", err)
	}
	if mapping.Resource.Resource != "issuers" {
		t.Errorf("RESTMapping(Issuer): got resource %q, want issuers", mapping.Resource.Resource)
	}
	if got := fetches.Load(); got != 2 {
		t.Errorf("expected 2 discovery fetches after refresh, got %d", got)
	}

	// A genuinely unknown kind still fails, after refreshing.
	if _, err := mapper.RESTMapping(schema.GroupKind{Group: "nonexistent.example.com", Kind: "Widget"}, "v1"); err == nil {
		t.Errorf("expected error for unknown kind")
	} else if !meta.IsNoMatchError(err) {
		t.Errorf("expected NoMatchError, got %v", err)
	}
}
