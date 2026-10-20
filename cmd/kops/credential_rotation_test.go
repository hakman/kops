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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kops/cmd/kops/util"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/kubeconfig"
	"k8s.io/kops/pkg/pki"
	"k8s.io/kops/pkg/testutils"
	"k8s.io/kops/upup/pkg/fi"
)

func setupCredentialRotationTest(t *testing.T) (*util.Factory, *kops.Cluster, fi.Keystore, *pki.Certificate) {
	t.Helper()
	h := testutils.NewIntegrationTestHarness(t)
	t.Cleanup(h.Close)
	h.SetupMockAWS()
	f := util.NewFactory(&util.FactoryOptions{RegistryPath: "memfs://credential-rotation"})
	clientset, err := f.KopsClient()
	require.NoError(t, err)
	cluster, err := clientset.CreateCluster(context.Background(), testutils.BuildMinimalClusterAWS("rotation.example.com"))
	require.NoError(t, err)
	keyStore, err := clientset.KeyStore(cluster)
	require.NoError(t, err)
	ca, key, _, err := pki.IssueCert(context.Background(), &pki.IssueCertRequest{Type: "ca"}, nil)
	require.NoError(t, err)
	keyset, err := fi.NewKeyset(ca, key)
	require.NoError(t, err)
	require.NoError(t, keyStore.StoreKeyset(context.Background(), fi.CertificateIDCA, keyset))
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "config"))
	return f, cluster, keyStore, ca
}

func TestGeneratedCredentialsAcrossCommandStages(t *testing.T) {
	testGeneratedCredentialsAcrossCommandStages(t, nil)
}

func testGeneratedCredentialsAcrossCommandStages(t *testing.T, additionalStage func(context.Context, *util.Factory, *kops.Cluster, kubeconfig.CreateKubecfgOptions)) {
	t.Helper()
	f, cluster, keyStore, ca := setupCredentialRotationTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	serverCert, serverKey, _, err := pki.IssueCert(ctx, &pki.IssueCertRequest{
		Type: "server", Signer: fi.CertificateIDCA, AlternateNames: []string{cluster.APIInternalName()},
	}, fi.NewPKIKeystoreAdapter(keyStore))
	require.NoError(t, err)
	certData, err := serverCert.AsBytes()
	require.NoError(t, err)
	keyData, err := serverKey.AsBytes()
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(certData, keyData)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	var mutex sync.Mutex
	var certificates []*x509.Certificate
	receivedCertificates := func() []*x509.Certificate {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]*x509.Certificate(nil), certificates...)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "missing certificate", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		mutex.Lock()
		certificates = append(certificates, cert)
		mutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/pods" {
			io.WriteString(w, `{"apiVersion":"v1","kind":"PodList","items":[]}`)
		} else {
			io.WriteString(w, `{"apiVersion":"v1","kind":"NodeList","items":[]}`)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}, ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()

	// A short real lifetime checks the production clock and factory wiring;
	// detailed expiry/refresh boundaries use a fake clock in pkg/kubeconfig.
	options := kubeconfig.CreateKubecfgOptions{Admin: 3 * time.Second, OverrideAPIServer: server.URL, CreateKubecfg: true}
	config, err := f.RESTConfig(ctx, cluster, options)
	require.NoError(t, err)
	initial, err := pki.ParsePEMCertificate(config.CertData)
	require.NoError(t, err)
	oldClient, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	oldDynamic, err := f.DynamicClient(ctx, cluster, options)
	require.NoError(t, err)
	rolling := &RollingUpdateOptions{}
	rolling.InitDefaults()
	rolling.ClusterName = cluster.Name
	rolling.CreateKubecfgOptions = options
	rolling.InstanceGroups = []string{"missing"}
	// Stop after node discovery, before any cloud mutations.
	require.ErrorContains(t, RunRollingUpdateCluster(ctx, f, io.Discard, rolling), `InstanceGroup "missing" not found`)
	require.Len(t, receivedCertificates(), 1)
	clientset, err := f.KopsClient()
	require.NoError(t, err)
	_, err = clientset.InstanceGroupsFor(cluster).Create(ctx, &kops.InstanceGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "nodes"},
		Spec:       kops.InstanceGroupSpec{Role: kops.InstanceGroupRoleNode},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	validation := &ValidateClusterOptions{}
	validation.InitDefaults()
	validation.ClusterName = cluster.Name
	validation.CreateKubecfgOptions = options
	// The empty mock cluster need not validate, but validation must reach the API.
	_, _ = RunValidateCluster(ctx, f, io.Discard, validation)
	initialRequests := len(receivedCertificates())
	require.Greater(t, initialRequests, 1)

	timer := time.NewTimer(time.Until(initial.Certificate.NotAfter.Add(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err = oldClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(t, err, "client created before expiry must renew")
	_, err = oldDynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "nodes"}).List(ctx, metav1.ListOptions{})
	require.NoError(t, err, "cached dynamic client must renew")
	require.ErrorContains(t, RunRollingUpdateCluster(ctx, f, io.Discard, rolling), `InstanceGroup "missing" not found`)
	require.Len(t, receivedCertificates(), initialRequests+3)

	// Validation must continue using the cached connection after credentials expire.
	_, _ = RunValidateCluster(ctx, f, io.Discard, validation)
	require.Greater(t, len(receivedCertificates()), initialRequests+3, "validation must reach the API after expiry")
	if additionalStage != nil {
		beforeStage := len(receivedCertificates())
		additionalStage(ctx, f, cluster, options)
		require.Len(t, receivedCertificates(), beforeStage+1, "additional stage must reach the API with renewed credentials")
	}
	received := receivedCertificates()
	cached, err := f.RESTConfig(ctx, cluster.DeepCopy(), options)
	require.NoError(t, err)
	require.True(t, config == cached, "stages must reuse the connection configuration")
	for _, cert := range received[initialRequests:] {
		require.NotEqual(t, initial.Certificate.SerialNumber, cert.SerialNumber)
		require.Equal(t, received[initialRequests].SerialNumber, cert.SerialNumber, "reuse the renewed credential")
	}
	_, err = os.Stat(os.Getenv("KUBECONFIG"))
	require.True(t, os.IsNotExist(err), "internal renewal must not write kubeconfig")
}

func TestCredentialRotationDefaults(t *testing.T) {
	f, cluster, _, _ := setupCredentialRotationTest(t)
	before := time.Now()
	config, err := f.RESTConfig(context.Background(), cluster, kubeconfig.CreateKubecfgOptions{})
	require.NoError(t, err)
	cert, err := pki.ParsePEMCertificate(config.CertData)
	require.NoError(t, err)
	require.WithinDuration(t, before.Add(kubeconfig.DefaultKubecfgAdminLifetime), cert.Certificate.NotAfter, 5*time.Second)
	require.NotNil(t, config.WrapTransport, "reconcile's default credentials must renew")
	cmd := NewCmdRollingUpdateCluster(nil, io.Discard)
	require.NoError(t, cmd.ParseFlags([]string{"--admin=37m"}))
	lifetime, err := cmd.Flags().GetDuration("admin")
	require.NoError(t, err)
	require.Equal(t, 37*time.Minute, lifetime)
}

func TestUseKubeconfigKeepsExecCredentialRefresh(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("test credential helper requires sh")
	}
	f, cluster, _, _ := setupCredentialRotationTest(t)
	var mutex sync.Mutex
	var tokens []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		tokens = append(tokens, r.Header.Get("Authorization"))
		mutex.Unlock()
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("must not replace the user's identity with admin")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"apiVersion":"v1","kind":"NodeList","items":[]}`)
	}))
	defer server.Close()
	// The first exec credential is already expired so client-go refreshes it
	// on the next request, without sleeps or changes to its clock.
	script := `token=first
expiry=2000-01-01T00:00:00Z
if [ -f "$ROTATION_TEST_MARKER" ]; then token=second; expiry=2099-01-01T00:00:00Z; fi
touch "$ROTATION_TEST_MARKER"
printf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"%s","expirationTimestamp":"%s"}}' "$token" "$expiry"`
	config := clientcmdapi.NewConfig()
	config.Clusters[cluster.Name] = &clientcmdapi.Cluster{Server: server.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}
	config.Contexts[cluster.Name] = &clientcmdapi.Context{Cluster: cluster.Name, AuthInfo: "operator"}
	config.AuthInfos["operator"] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		Command: shell, Args: []string{"-c", script}, APIVersion: "client.authentication.k8s.io/v1",
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		Env:             []clientcmdapi.ExecEnvVar{{Name: "ROTATION_TEST_MARKER", Value: filepath.Join(t.TempDir(), "marker")}},
	}}
	require.NoError(t, clientcmd.WriteToFile(*config, os.Getenv("KUBECONFIG")))
	before, err := os.ReadFile(os.Getenv("KUBECONFIG"))
	require.NoError(t, err)
	ctx := context.Background()
	reused, err := f.RESTConfig(ctx, cluster, kubeconfig.CreateKubecfgOptions{UseKubeconfig: true, Admin: time.Second})
	require.NoError(t, err)
	require.Nil(t, reused.WrapTransport)
	require.Empty(t, reused.CertData)
	require.Equal(t, config.AuthInfos["operator"].Exec, reused.ExecProvider)
	client, err := kubernetes.NewForConfig(reused)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
	}
	mutex.Lock()
	gotTokens := append([]string(nil), tokens...)
	mutex.Unlock()
	require.Equal(t, []string{"Bearer first", "Bearer second", "Bearer second"}, gotTokens)
	after, err := os.ReadFile(os.Getenv("KUBECONFIG"))
	require.NoError(t, err)
	require.Equal(t, before, after)
}
