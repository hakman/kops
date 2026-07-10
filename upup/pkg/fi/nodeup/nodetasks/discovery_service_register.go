/*
Copyright 2025 The Kubernetes Authors.

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

package nodetasks

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"k8s.io/klog/v2"

	discoveryapi "k8s.io/kops/discovery/apis/discovery.kops.k8s.io/v1alpha1"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/nodeup/local"
)

// DiscoveryServiceRegisterTask is responsible for registering with the discovery service.
type DiscoveryServiceRegisterTask struct {
	// Name is a reference for our task
	Name string

	// DiscoveryService is the discovery service to register with (including the universe ID prefix)
	DiscoveryService string

	// RegisterNamespace is the namespace to use for registration with the discovery service
	RegisterNamespace string

	// RegisterName is the name to use for registration with the discovery service
	RegisterName string

	// ClientCert is the client certificate to present when registering
	ClientCert fi.Resource

	// ClientKey is the client key to use when registering
	ClientKey fi.Resource

	// ClientCA is the CA certificate to use when registering,
	// we include it in the bundle presented to the server,
	// as it is likely self-signed.
	ClientCA fi.Resource

	// JWKS is the set of public keys to advertise through the discovery service.
	JWKS []JSONWebKey
}

// JSONWebKey wraps discoveryapi.JSONWebKey, to implement dependency discovery.
type JSONWebKey struct {
	discoveryapi.JSONWebKey
}

var _ fi.NodeupHasDependencies = (*JSONWebKey)(nil)

// GetDependencies returns the dependencies for the JSONWebKey; there are none.
func (j *JSONWebKey) GetDependencies(tasks map[string]fi.NodeupTask) []fi.NodeupTask {
	return nil
}

var _ fi.NodeupTask = (*UpdateEtcHostsTask)(nil)

func (e *DiscoveryServiceRegisterTask) String() string {
	return fmt.Sprintf("DiscoveryServiceRegisterTask: %s", e.Name)
}

var _ fi.HasName = (*DiscoveryServiceRegisterTask)(nil)

func (f *DiscoveryServiceRegisterTask) GetName() *string {
	return &f.Name
}

func (e *DiscoveryServiceRegisterTask) Find(c *fi.NodeupContext) (*DiscoveryServiceRegisterTask, error) {
	// We always register with the service.
	return nil, nil
}

func (e *DiscoveryServiceRegisterTask) Run(c *fi.NodeupContext) error {
	return fi.NodeupDefaultDeltaRunMethod(e, c)
}

func (_ *DiscoveryServiceRegisterTask) CheckChanges(a, e, changes *DiscoveryServiceRegisterTask) error {
	return nil
}

func (_ *DiscoveryServiceRegisterTask) RenderLocal(t *local.LocalTarget, a, e, changes *DiscoveryServiceRegisterTask) error {
	ctx := context.TODO()

	log := klog.FromContext(ctx)

	clientCert, err := fi.ResourceAsBytes(e.ClientCert)
	if err != nil {
		return err
	}
	clientKey, err := fi.ResourceAsBytes(e.ClientKey)
	if err != nil {
		return err
	}
	clientCA, err := fi.ResourceAsBytes(e.ClientCA)
	if err != nil {
		return err
	}

	clientCertBundle := []byte{}
	clientCertBundle = append(clientCertBundle, clientCert...)
	clientCertBundle = append(clientCertBundle, clientCA...)

	httpClient, err := buildDiscoveryHTTPClient(clientCertBundle, clientKey)
	if err != nil {
		return err
	}

	result, err := e.register(ctx, httpClient)
	if err != nil {
		return err
	}
	log.Info("registered with discovery service", "result", *result)

	return nil
}

// buildDiscoveryHTTPClient builds an HTTP client that presents the given
// client certificate bundle; the server certificate is verified against the
// system roots.
func buildDiscoveryHTTPClient(clientCertBundle, clientKey []byte) (*http.Client, error) {
	clientCertificate, err := tls.X509KeyPair(clientCertBundle, clientKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing client certificate: %w", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
		},
	}
	return &http.Client{Transport: transport}, nil
}

// register sends our DiscoveryEndpoint to the discovery service, with a
// server-side-apply PATCH request matching the one sent by the client-go
// dynamic client.  We build the request by hand so that nodeup does not need
// to link the dynamic client and the serializer machinery it drags in.
func (e *DiscoveryServiceRegisterTask) register(ctx context.Context, httpClient *http.Client) (*discoveryapi.DiscoveryEndpoint, error) {
	spec := discoveryapi.DiscoveryEndpointSpec{}

	spec.OIDC = &discoveryapi.OIDCSpec{}

	for _, jwk := range e.JWKS {
		spec.OIDC.Keys = append(spec.OIDC.Keys, jwk.JSONWebKey)
	}

	ep := &discoveryapi.DiscoveryEndpoint{
		Spec: spec,
	}

	ep.Kind = "DiscoveryEndpoint"
	ep.APIVersion = "discovery.kops.k8s.io/v1alpha1"

	ep.Name = e.RegisterName
	ep.Namespace = e.RegisterNamespace

	body, err := json.Marshal(ep)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DiscoveryEndpoint: %w", err)
	}

	host := e.DiscoveryService
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("invalid discovery service %q: %w", e.DiscoveryService, err)
	}
	gvr := discoveryapi.DiscoveryEndpointGVR
	u.Path = path.Join(u.Path, "apis", gvr.Group, gvr.Version, "namespaces", ep.Namespace, gvr.Resource, ep.Name)
	query := u.Query()
	query.Set("fieldManager", "nodeup-register")
	query.Set("force", "false")
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/apply-patch+yaml")
	req.Header.Set("Accept", "application/json")

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register with discovery service: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery service response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("failed to register with discovery service: unexpected response %q: %s", response.Status, strings.TrimSpace(string(responseBody)))
	}

	var result discoveryapi.DiscoveryEndpoint
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse discovery service response: %w", err)
	}
	return &result, nil
}
