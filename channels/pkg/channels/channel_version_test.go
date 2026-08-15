/*
Copyright 2021 The Kubernetes Authors.

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

package channels

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	fakekubernetes "k8s.io/kops/pkg/slimclient/fake"
)

func newFakeDynamicClient(objects ...runtime.Object) *fakedynamic.FakeDynamicClient {
	return fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{issuerGVR: "IssuerList"}, objects...)
}

func Test_IsPKIInstalled(t *testing.T) {
	ctx := context.Background()
	fakek8s := fakekubernetes.NewClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-sysetem",
		},
	})
	fakecm := newFakeDynamicClient()

	channel := &Channel{
		Name: "test",
	}
	isInstalled, err := channel.IsPKIInstalled(ctx, fakek8s, fakecm)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if isInstalled {
		t.Error("claims PKI installed when it is not")
	}

	fakek8s = fakekubernetes.NewClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-sysetem",
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ca",
				Namespace: "kube-system",
			},
		},
	)
	fakecm = newFakeDynamicClient(
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "cert-manager.io/v1",
				"kind":       "Issuer",
				"metadata": map[string]interface{}{
					"name":      "test",
					"namespace": "kube-system",
				},
			},
		},
	)

	isInstalled, err = channel.IsPKIInstalled(ctx, fakek8s, fakecm)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !isInstalled {
		t.Error("claims PKI is not installed when it is")
	}
}
