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

package kubeconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/rest"
	"k8s.io/kops/pkg/pki"
	"k8s.io/kops/upup/pkg/fi"
)

// ToRESTConfigWithRotation builds an internal client configuration that renews
// kOps-generated admin certificates. Exported kubeconfigs remain static, and
// configurations loaded from a user's kubeconfig must not use this method.
func (b *KubeconfigBuilder) ToRESTConfigWithRotation(keyStore fi.KeystoreReader, lifetime time.Duration) (*rest.Config, error) {
	config, err := b.ToRESTConfig()
	if err != nil {
		return nil, err
	}
	cert, err := pki.ParsePEMCertificate(b.ClientCert)
	if err != nil {
		return nil, err
	}
	issue := func(ctx context.Context) ([]byte, []byte, error) {
		request := &pki.IssueCertRequest{
			Signer: fi.CertificateIDCA, Type: "client",
			Subject: cert.Subject, Validity: lifetime,
		}
		certificate, key, _, err := pki.IssueCert(ctx, request, fi.NewPKIKeystoreAdapter(keyStore))
		if err != nil {
			return nil, nil, err
		}
		certData, err := certificate.AsBytes()
		if err != nil {
			return nil, nil, err
		}
		keyData, err := key.AsBytes()
		return certData, keyData, err
	}
	return withCertificateRotation(config, lifetime, issue, time.Now)
}

// rotatingTransport shares a credential and connection pool across clients made
// from the same REST config, including clients retained across reconcile stages.
type rotatingTransport struct {
	// A channel lock lets requests cancel while waiting for another renewal.
	lock          chan struct{}
	config        *rest.Config
	transport     http.RoundTripper
	refreshAt     time.Time
	refreshBefore time.Duration
	now           func() time.Time
	issue         func(context.Context) ([]byte, []byte, error)
	refreshErr    error
	retryAt       time.Time
}

func withCertificateRotation(config *rest.Config, lifetime time.Duration, issue func(context.Context) ([]byte, []byte, error), now func() time.Time) (*rest.Config, error) {
	if lifetime <= 0 {
		return nil, fmt.Errorf("admin certificate lifetime must be positive")
	}
	r := &rotatingTransport{
		lock:   make(chan struct{}, 1),
		config: rest.CopyConfig(config), issue: issue, now: now,
		// Allow for clock skew without exhausting short custom lifetimes.
		refreshBefore: min(5*time.Minute, lifetime/5),
	}
	if err := r.installCertificate(config.CertData, config.KeyData); err != nil {
		return nil, err
	}
	// Keep client-go's HTTP wrappers (user agent, debugging, etc.) outside the
	// rotating TLS transport. Do not mutate a transport in client-go's cache.
	config.Wrap(func(http.RoundTripper) http.RoundTripper { return r })
	return config, nil
}

// installCertificate is called before publication or with lock held.
func (r *rotatingTransport) installCertificate(certData, keyData []byte) error {
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	refreshAt := leaf.NotAfter.Add(-r.refreshBefore)
	if !r.now().Before(refreshAt) {
		return fmt.Errorf("issued admin certificate expires too soon: %s", leaf.NotAfter)
	}
	config := rest.CopyConfig(r.config)
	config.CertData, config.KeyData = certData, keyData
	rt, err := rest.TransportFor(config)
	if err != nil {
		return err
	}
	// A TLS callback alone would leave pooled connections authenticated with the
	// old certificate. New requests must use a new pool. Active requests/watches
	// can finish on the old transport without being interrupted by renewal.
	if r.transport != nil {
		utilnet.CloseIdleConnectionsFor(r.transport)
	}
	r.transport = rt
	r.refreshAt = refreshAt
	return nil
}

func (r *rotatingTransport) transportFor(ctx context.Context) (http.RoundTripper, error) {
	select {
	case r.lock <- struct{}{}:
		defer func() { <-r.lock }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.now().Before(r.refreshAt) {
		return r.transport, nil
	}
	if r.refreshErr != nil && r.now().Before(r.retryAt) {
		return nil, r.refreshErr
	}
	cert, key, err := r.issue(ctx)
	if err == nil {
		err = r.installCertificate(cert, key)
	}
	if err != nil {
		err = fmt.Errorf("renewing kOps admin certificate: %w", err)
		// Bound repeated failures across concurrent callers; never send a request
		// using the stale credential or retry API mutations automatically.
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			r.refreshErr = err
			r.retryAt = r.now().Add(min(10*time.Second, r.refreshBefore))
		}
		return nil, err
	}
	r.refreshErr = nil
	return r.transport, nil
}

func (r *rotatingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	rt, err := r.transportFor(request.Context())
	if err != nil {
		// RoundTripper owns the body even when renewal fails before sending.
		if request.Body != nil {
			request.Body.Close()
		}
		return nil, err
	}
	return rt.RoundTrip(request)
}

func (r *rotatingTransport) CloseIdleConnections() {
	r.lock <- struct{}{}
	defer func() { <-r.lock }()
	utilnet.CloseIdleConnectionsFor(r.transport)
}
