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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kops/pkg/pki"
	"k8s.io/kops/upup/pkg/fi"
)

type certificateTestClock struct {
	nanos atomic.Int64
}

func (c *certificateTestClock) Now() time.Time       { return time.Unix(0, c.nanos.Load()) }
func (c *certificateTestClock) Step(d time.Duration) { c.nanos.Add(int64(d)) }

type certificateTestServer struct {
	clock        *certificateTestClock
	ca           *x509.Certificate
	key          *ecdsa.PrivateKey
	server       *httptest.Server
	mutex        sync.Mutex
	connections  []string
	certificates []*x509.Certificate
	protocols    []int
}

func newCertificateTestServer(t *testing.T, http2 bool) *certificateTestServer {
	t.Helper()
	f := &certificateTestServer{clock: &certificateTestClock{}}
	f.clock.nanos.Store(time.Now().Truncate(time.Second).UnixNano())
	var err error
	f.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: f.clock.Now().Add(-time.Hour), NotAfter: f.clock.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, f.key.Public(), f.key)
	require.NoError(t, err)
	f.ca, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(f.ca)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mutex.Lock()
		f.connections = append(f.connections, r.RemoteAddr)
		f.protocols = append(f.protocols, r.ProtoMajor)
		f.certificates = append(f.certificates, r.TLS.PeerCertificates...)
		f.mutex.Unlock()
		// kube-apiserver verifies the client certificate on every request,
		// including requests reusing an established TLS connection.
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "missing client certificate", http.StatusUnauthorized)
			return
		}
		_, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots: roots, CurrentTime: f.clock.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") == "true" {
			io.WriteString(w, `{"type":"ADDED","object":{"apiVersion":"v1","kind":"Node","metadata":{"name":"node"}}}`+"\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.Method == http.MethodPost {
			io.WriteString(w, `{"apiVersion":"v1","kind":"Status","status":"Success"}`)
			return
		}
		io.WriteString(w, `{"apiVersion":"v1","kind":"NodeList","items":[]}`)
	}))
	f.server.EnableHTTP2 = http2
	f.server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

func TestRotatingClientCertificate(t *testing.T) {
	for _, lifetime := range []time.Duration{DefaultKubecfgAdminLifetime, 30 * time.Minute, 10 * time.Second} {
		for _, http2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/http2=%t", lifetime, http2), func(t *testing.T) {
				f := newCertificateTestServer(t, http2)
				config, err := f.builder(t, lifetime).ToRESTConfig()
				require.NoError(t, err)
				var issued atomic.Int32
				config, err = withCertificateRotation(config, lifetime, func(context.Context) ([]byte, []byte, error) {
					issued.Add(1)
					b := f.builder(t, lifetime)
					return b.ClientCert, b.ClientKey, nil
				}, f.clock.Now)
				require.NoError(t, err)
				client, err := kubernetes.NewForConfig(config)
				require.NoError(t, err)
				dynamicClient, err := dynamic.NewForConfig(config)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				list := func() error {
					_, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
					return err
				}
				require.NoError(t, list())
				f.clock.Step(lifetime - min(5*time.Minute, lifetime/5) - time.Second)
				require.NoError(t, list())
				require.Zero(t, issued.Load())
				require.Equal(t, f.connections[0], f.connections[1])
				watch, err := client.CoreV1().Nodes().Watch(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				defer watch.Stop()
				<-watch.ResultChan()
				f.clock.Step(time.Second)
				// Concurrent drain/validation callers and a separately created dynamic
				// client must all share the renewal and use the new connection pool.
				errors := make(chan error, 12)
				for i := 0; i < cap(errors); i++ {
					go func() { errors <- list() }()
				}
				for i := 0; i < cap(errors); i++ {
					require.NoError(t, <-errors)
				}
				require.EqualValues(t, 1, issued.Load())
				f.clock.Step(min(5*time.Minute, lifetime/5) + time.Second)
				require.NoError(t, list(), "the original client must work beyond its initial certificate lifetime")
				_, err = dynamicClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "nodes"}).List(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				require.NoError(t, client.CoreV1().Pods("default").EvictV1(ctx, &policyv1.Eviction{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"}}))
				// An active watch is not interrupted when the pool is replaced.
				select {
				case event, ok := <-watch.ResultChan():
					t.Fatalf("watch ended during renewal: event=%v open=%t", event, ok)
				default:
				}
				watch.Stop()
				watch, err = client.CoreV1().Nodes().Watch(ctx, metav1.ListOptions{})
				require.NoError(t, err, "reconnected watches must use renewed credentials")
				<-watch.ResultChan()
				watch.Stop()
				require.EqualValues(t, 1, issued.Load())
				f.clock.Step(lifetime)
				require.NoError(t, list(), "renewal must continue over successive certificate lifetimes")
				require.EqualValues(t, 2, issued.Load())
				f.mutex.Lock()
				defer f.mutex.Unlock()
				require.NotEqual(t, f.connections[0], f.connections[len(f.connections)-1])
				require.NotEqual(t, f.certificates[0].SerialNumber, f.certificates[len(f.certificates)-1].SerialNumber)
				wantProtocol := 1
				if http2 {
					wantProtocol = 2
				}
				for _, protocol := range f.protocols {
					require.Equal(t, wantProtocol, protocol)
				}
			})
		}
	}
}

func TestCertificateRenewalFailure(t *testing.T) {
	for _, failure := range []string{"issuer", "invalid key", "expired certificate", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			f := newCertificateTestServer(t, false)
			initial := f.builder(t, time.Minute)
			config, err := initial.ToRESTConfig()
			require.NoError(t, err)
			issued := 0
			failing := true
			config, err = withCertificateRotation(config, time.Minute, func(ctx context.Context) ([]byte, []byte, error) {
				issued++
				if failing {
					switch failure {
					case "issuer":
						return nil, nil, errors.New("signing key unavailable")
					case "invalid key":
						return initial.ClientCert, []byte("invalid"), nil
					case "expired certificate":
						return initial.ClientCert, initial.ClientKey, nil
					case "canceled":
						return nil, nil, context.Canceled
					}
				}
				b := f.builder(t, time.Minute)
				return b.ClientCert, b.ClientKey, nil
			}, f.clock.Now)
			require.NoError(t, err)
			client, err := kubernetes.NewForConfig(config)
			require.NoError(t, err)
			list := func(ctx context.Context) error {
				_, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
				return err
			}
			require.NoError(t, list(context.Background()))
			f.clock.Step(time.Minute + time.Second)
			require.ErrorContains(t, list(context.Background()), "renewing kOps admin certificate")
			require.Len(t, f.connections, 1, "failed renewal must not send an expired credential")
			require.Equal(t, 1, issued, "no internal retry loop")
			if failure != "canceled" {
				require.ErrorContains(t, list(context.Background()), "renewing kOps admin certificate")
				require.Equal(t, 1, issued, "failed renewal must be throttled")
				f.clock.Step(10 * time.Second)
			}
			failing = false
			require.NoError(t, list(context.Background()))
			require.Equal(t, 2, issued)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.ErrorIs(t, list(ctx), context.Canceled)
			require.Equal(t, 2, issued)
		})
	}
}

type renewalRequestBody struct {
	io.Reader
	closes atomic.Int32
}

func (b *renewalRequestBody) Close() error {
	b.closes.Add(1)
	return nil
}

func TestCertificateRenewalClosesRequestBody(t *testing.T) {
	for _, failure := range []string{"issuer", "canceled", "deadline"} {
		t.Run(failure, func(t *testing.T) {
			f := newCertificateTestServer(t, false)
			config, err := f.builder(t, time.Minute).ToRESTConfig()
			require.NoError(t, err)
			issuerErr := errors.New("signing key unavailable")
			issued := 0
			config, err = withCertificateRotation(config, time.Minute, func(context.Context) ([]byte, []byte, error) {
				issued++
				return nil, nil, issuerErr
			}, f.clock.Now)
			require.NoError(t, err)
			client, err := rest.HTTPClientFor(config)
			require.NoError(t, err)
			t.Cleanup(client.CloseIdleConnections)
			f.clock.Step(time.Minute)

			ctx := context.Background()
			wantErr := issuerErr
			wantIssued := 1
			if failure == "canceled" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx, wantErr, wantIssued = canceled, context.Canceled, 0
			} else if failure == "deadline" {
				expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				ctx, wantErr, wantIssued = expired, context.DeadlineExceeded, 0
			}

			// The second attempt also covers the renewal-error backoff path.
			for range 2 {
				body := &renewalRequestBody{Reader: strings.NewReader(`{"kind":"Eviction"}`)}
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.server.URL, body)
				require.NoError(t, err)
				response, err := client.Do(request)
				require.ErrorIs(t, err, wantErr)
				require.Nil(t, response)
				require.EqualValues(t, 1, body.closes.Load(), "failed requests must release their bodies")
			}
			require.Equal(t, wantIssued, issued)
			require.Empty(t, f.connections, "failed renewal must not send the request")
		})
	}
}

func TestCertificateRenewalCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			f := newCertificateTestServer(t, false)
			config, err := f.builder(t, time.Minute).ToRESTConfig()
			require.NoError(t, err)
			started := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var requests sync.WaitGroup
			defer func() { unblock(); requests.Wait() }()
			var issued atomic.Int32
			// Prebuild the replacement so the test issuer only waits and returns.
			f.clock.Step(time.Minute)
			renewed := f.builder(t, time.Minute)
			f.clock.Step(-time.Minute)
			config, err = withCertificateRotation(config, time.Minute, func(ctx context.Context) ([]byte, []byte, error) {
				if issued.Add(1) == 1 {
					close(started)
				}
				<-release
				return renewed.ClientCert, renewed.ClientKey, nil
			}, f.clock.Now)
			require.NoError(t, err)
			client, err := rest.HTTPClientFor(config)
			require.NoError(t, err)
			t.Cleanup(client.CloseIdleConnections)
			get := func(ctx context.Context) error {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.server.URL, nil)
				if err != nil {
					return err
				}
				response, err := client.Do(request)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					return fmt.Errorf("unexpected response: %s", response.Status)
				}
				return nil
			}
			startRequest := func(ctx context.Context) <-chan error {
				done := make(chan error, 1)
				requests.Add(1)
				go func() { defer requests.Done(); done <- get(ctx) }()
				return done
			}
			f.clock.Step(time.Minute)
			first := startRequest(context.Background())
			<-started

			ctx, cancel := context.WithCancel(context.Background())
			wantErr := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
				wantErr = context.DeadlineExceeded
			}
			defer cancel()
			canceled := startRequest(ctx)
			if !deadline {
				cancel()
			}
			select {
			case err := <-canceled:
				require.ErrorIs(t, err, wantErr)
			case <-time.After(2 * time.Second):
				t.Fatal("request ignored cancellation while another request renewed its certificate")
			}
			unblock()
			require.NoError(t, <-first, "canceling a waiter must not interrupt renewal")
			require.NoError(t, get(context.Background()), "renewed credentials remain usable")
			require.EqualValues(t, 1, issued.Load(), "concurrent requests must share renewal")
		})
	}
}

func TestAdminCertificateRenewalLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Minute, 2 * time.Hour, DefaultKubecfgAdminLifetime} {
		t.Run(lifetime.String(), func(t *testing.T) {
			f := newCertificateTestServer(t, false)
			keyset, err := fi.NewKeyset(&pki.Certificate{Certificate: f.ca}, &pki.PrivateKey{Key: f.key})
			require.NoError(t, err)
			keyStore := fakeKeyStore{FindKeysetFn: func(string) (*fi.Keyset, error) { return keyset, nil }}
			config, err := f.builder(t, lifetime).ToRESTConfigWithRotation(keyStore, lifetime)
			require.NoError(t, err)
			r := config.WrapTransport(nil).(*rotatingTransport)
			// Force a renewal without changing the production PKI clock.
			r.refreshAt = time.Time{}
			before := time.Now()
			client, err := kubernetes.NewForConfig(config)
			require.NoError(t, err)
			_, err = client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			cert := f.certificates[0]
			require.WithinDuration(t, before.Add(lifetime), cert.NotAfter, 5*time.Second)
			require.Equal(t, "kubecfg-test", cert.Subject.CommonName)
			require.Equal(t, []string{"system:masters"}, cert.Subject.Organization)
		})
	}
}

func (f *certificateTestServer) builder(t *testing.T, lifetime time.Duration) *KubeconfigBuilder {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "kubecfg-test", Organization: []string{"system:masters"}},
		NotBefore: f.clock.Now().Add(-time.Minute), NotAfter: f.clock.Now().Add(lifetime),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, f.key.Public(), f.key)
	require.NoError(t, err)
	key, err := x509.MarshalECPrivateKey(f.key)
	require.NoError(t, err)
	return &KubeconfigBuilder{
		Server:     f.server.URL,
		CACerts:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}),
		ClientCert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		ClientKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}),
	}
}

func TestStaticClientCertificateExpires(t *testing.T) {
	f := newCertificateTestServer(t, false)
	config, err := f.builder(t, time.Hour).ToRESTConfig()
	require.NoError(t, err)
	httpClient, err := rest.HTTPClientFor(config)
	require.NoError(t, err)
	client, err := kubernetes.NewForConfigAndClient(config, httpClient)
	require.NoError(t, err)
	_, err = client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	f.clock.Step(time.Hour + time.Second)
	_, err = client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	require.True(t, apierrors.IsUnauthorized(err), "expected expired certificate rejection, got %v", err)
	require.Equal(t, f.connections[0], f.connections[1], "expiry must also affect pooled connections")

	// Replacing cached REST config bytes does not update existing clients,
	// even when they open a new TLS connection.
	replacement := f.builder(t, time.Hour)
	config.CertData, config.KeyData = replacement.ClientCert, replacement.ClientKey
	utilnet.CloseIdleConnectionsFor(httpClient.Transport)
	_, err = client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	require.True(t, apierrors.IsUnauthorized(err), "expected stale transport credential, got %v", err)
	require.NotEqual(t, f.connections[1], f.connections[2])
}
