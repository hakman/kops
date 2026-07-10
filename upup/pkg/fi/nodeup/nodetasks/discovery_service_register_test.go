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

package nodetasks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	discoveryapi "k8s.io/kops/discovery/apis/discovery.kops.k8s.io/v1alpha1"
	"k8s.io/kops/discovery/pkg/discovery"
)

// TestDiscoveryServiceRegister registers with a real discovery service over
// mTLS, verifying that the hand-built server-side-apply request is accepted
// by the server and round-trips the endpoint.
func TestDiscoveryServiceRegister(t *testing.T) {
	ctx := context.TODO()

	server := httptest.NewUnstartedServer(discovery.NewServer(discovery.NewMemoryStore()))
	server.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
	}
	server.StartTLS()
	defer server.Close()

	ca, caKey := generateTestCA(t, "test-universe-ca")
	clientCert, clientKey := generateTestClientCert(t, "node-1", ca, caKey)

	hash := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
	universeID := hex.EncodeToString(hash[:])

	task := &DiscoveryServiceRegisterTask{
		Name:              "register",
		DiscoveryService:  server.URL + "/" + universeID,
		RegisterNamespace: "default",
		// The discovery service requires the registered name to match the client certificate CN.
		RegisterName: "node-1",
		JWKS: []JSONWebKey{
			{JSONWebKey: discoveryapi.JSONWebKey{Use: "sig", KeyType: "RSA", KeyID: "key1", Algorithm: "RS256", N: "modulus", E: "AQAB"}},
		},
	}

	// Build the client the same way RenderLocal does.
	var clientCertBundle bytes.Buffer
	if err := pem.Encode(&clientCertBundle, &pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw}); err != nil {
		t.Fatalf("failed to encode client certificate: %v", err)
	}
	if err := pem.Encode(&clientCertBundle, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}); err != nil {
		t.Fatalf("failed to encode CA certificate: %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	httpClient, err := buildDiscoveryHTTPClient(clientCertBundle.Bytes(), clientKeyPEM)
	if err != nil {
		t.Fatalf("failed to build HTTP client: %v", err)
	}
	// The production client verifies the server against system roots;
	// for the test we have to trust the test server's certificate.
	serverCAs := x509.NewCertPool()
	serverCAs.AddCert(server.Certificate())
	httpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = serverCAs

	result, err := task.register(ctx, httpClient)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	if result.Name != "node-1" {
		t.Errorf("unexpected result name %q", result.Name)
	}
	if result.Spec.OIDC == nil || len(result.Spec.OIDC.Keys) != 1 {
		t.Fatalf("unexpected result OIDC keys: %+v", result.Spec)
	}
	if result.Spec.OIDC.Keys[0] != task.JWKS[0].JSONWebKey {
		t.Errorf("JWKS did not round-trip: %+v", result.Spec.OIDC.Keys[0])
	}

	// Registering under a name that does not match the client certificate must fail.
	task.RegisterName = "node-2"
	if _, err := task.register(ctx, httpClient); err == nil {
		t.Errorf("expected registration under mismatched name to fail")
	}
}

func generateTestCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	return cert, key
}

func generateTestClientCert(t *testing.T, cn string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}
	return cert, key
}
