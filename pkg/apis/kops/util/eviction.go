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

package util

import (
	"fmt"
	"slices"
	"strings"
)

// allocatableEvictionSignals are the eviction signals whose hard thresholds reduce the
// allocatable capacity of a node. The kubelet subtracts these thresholds from the node
// capacity, and Karpenter does the same when it computes the allocatable capacity of an
// instance type.
var allocatableEvictionSignals = []string{"memory.available", "nodefs.available"}

// AllocatableEvictionThresholds reads a kubelet hard eviction threshold list in the kOps
// "signal<value,signal<value" form and returns the thresholds that reduce the allocatable
// capacity of a node, as a map of signal to value. It parses the list the same way nodeup
// does for the kubelet configuration: signals and values are trimmed, and the last value
// wins for a repeated signal.
func AllocatableEvictionThresholds(evictionHard string) (map[string]string, error) {
	if evictionHard == "" {
		return nil, nil
	}
	result := make(map[string]string)
	for threshold := range strings.SplitSeq(evictionHard, ",") {
		signal, value, found := strings.Cut(threshold, "<")
		if !found {
			return nil, fmt.Errorf("invalid eviction threshold %q (expected signal<value)", threshold)
		}
		if signal = strings.TrimSpace(signal); slices.Contains(allocatableEvictionSignals, signal) {
			result[signal] = strings.TrimSpace(value)
		}
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}
