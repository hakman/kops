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

package model

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/kops/pkg/kubemanifest"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/nodeup/nodetasks"
)

// goRunnerLogDir is the host directory for the logs that /go-runner rotates. Only this directory is
// mounted into the pods, not all of /var/log.
const goRunnerLogDir = "/var/log/kubernetes"

// useGoRunnerLogRotation reports whether /go-runner in the Kubernetes server images rotates its log file.
// Starting with Kubernetes 1.36, the kube-apiserver, kube-controller-manager, kube-scheduler and kube-proxy
// images ship kube-log-runner as /go-runner, which supports --log-file-size and --log-file-age.
func (c *NodeupModelContext) useGoRunnerLogRotation() bool {
	return c.IsKubernetesGTE("1.36")
}

// goRunnerArgs makes the log file of a component writable by its container and returns the
// /go-runner arguments that run the component and copy its output to that file and to stdout.
func (c *NodeupModelContext) goRunnerArgs(pod *v1.Pod, container *v1.Container, component string) []string {
	binary := "/usr/local/bin/" + component

	if !c.useGoRunnerLogRotation() {
		logFile := "/var/log/" + component + ".log"
		kubemanifest.AddHostPathMapping(pod, container, "logfile", logFile, kubemanifest.WithReadWrite())
		return []string{
			"--log-file=" + logFile,
			"--also-stdout",
			binary,
		}
	}

	// Rotation renames the log file. A rename of a single-file bind mount fails with EBUSY,
	// and kube-log-runner then stops the component, so the directory is mounted.
	kubemanifest.AddHostPathMapping(pod, container, "varlogkubernetes", goRunnerLogDir, kubemanifest.WithReadWrite())
	return []string{
		"--log-file=" + goRunnerLogDir + "/" + component + ".log",
		// kube-log-runner has no limit on the number or total size of backups. It removes backups
		// older than --log-file-age, and only when it rotates. With 100MiB files and 6h, a component
		// that logs heavily keeps about the last 6 hours, as logrotate does with hourly checks,
		// "maxsize 100M" and "rotate 5".
		"--log-file-size=100Mi",
		"--log-file-age=6h",
		"--also-stdout",
		binary,
	}
}

// addGoRunnerLogFileTasks prepares the host for the log file of a component run by /go-runner.
func (c *NodeupModelContext) addGoRunnerLogFileTasks(ctx *fi.NodeupModelBuilderContext, component string) {
	logFile := "/var/log/" + component + ".log"

	if !c.useGoRunnerLogRotation() {
		ctx.AddTask(&nodetasks.File{
			Path:        logFile,
			Contents:    fi.NewStringResource(""),
			Type:        nodetasks.FileType_File,
			Mode:        s("0400"),
			IfNotExists: true,
		})
		return
	}

	// Several components share the directory, so each of them ensures it.
	ctx.EnsureTask(&nodetasks.File{
		Path: goRunnerLogDir,
		Type: nodetasks.FileType_Directory,
		Mode: s("0755"),
	})
	// The symlink keeps the log readable at /var/log/<component>.log. It is relative, so that it
	// also resolves where the host /var/log is mounted at another path, as in a log shipper pod.
	ctx.AddTask(&nodetasks.File{
		Path:    logFile,
		Type:    nodetasks.FileType_Symlink,
		Symlink: s("kubernetes/" + component + ".log"),
	})
}
