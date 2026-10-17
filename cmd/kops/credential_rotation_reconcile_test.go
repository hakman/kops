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
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/kops/cmd/kops/util"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/kubeconfig"
)

// This combined regression requires both credential renewal and the update fix
// that propagates connection options through reconcile's version check. Keep
// this file separate from either standalone fix when splitting the patches.
func TestGeneratedCredentialsAcrossReconcile(t *testing.T) {
	testGeneratedCredentialsAcrossCommandStages(t, func(ctx context.Context, f *util.Factory, cluster *kops.Cluster, options kubeconfig.CreateKubecfgOptions) {
		reconcile := &ReconcileClusterOptions{CreateKubecfgOptions: options}
		reconcile.InitDefaults()
		reconcile.ClusterName = cluster.Name
		reconcile.Yes = true
		// The incomplete cluster stops at apply validation, after the version check.
		require.Error(t, RunReconcileCluster(ctx, f, io.Discard, reconcile))
	})
}
