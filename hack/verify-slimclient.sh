#!/usr/bin/env bash

# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verifies that the binaries built on pkg/slimclient stay slim: importing the
# generated clientset, the per-group typed clients, the discovery client or
# controller-runtime's client links the marshalling code for every k8s.io/api
# group (they all register the full k8s.io/client-go/kubernetes/scheme),
# adding several MB per binary. See pkg/slimclient.

set -o errexit
set -o nounset
set -o pipefail

. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

cd "${KOPS_ROOT}"

# Package trees whose reachability defeats the slim client.
forbidden=(
  "k8s.io/client-go/kubernetes/scheme"
  "k8s.io/client-go/kubernetes/typed/"
  "k8s.io/client-go/discovery"
  "k8s.io/client-go/gentype"
  "sigs.k8s.io/controller-runtime/pkg/client"
)

# The API groups the slim binaries are expected to link.
allowed_api_packages=(
  "k8s.io/api/apidiscovery/v2"
  "k8s.io/api/core/v1"
  "k8s.io/api/networking/v1"
)

exit_code=0
for target in ./dns-controller/cmd/dns-controller ./channels/cmd/channels; do
  deps=$(go list -deps "${target}")

  for pkg in "${forbidden[@]}"; do
    if grep -q "^${pkg}" <<<"${deps}"; then
      echo "FAIL: ${target} links ${pkg}, which registers every k8s.io/api group."
      echo "      Use pkg/slimclient (or the dynamic client) instead."
      exit_code=1
    fi
  done

  api_packages=$(grep "^k8s.io/api/" <<<"${deps}" || true)
  while read -r pkg; do
    [ -z "${pkg}" ] && continue
    found=0
    for allowed in "${allowed_api_packages[@]}"; do
      if [ "${pkg}" = "${allowed}" ]; then
        found=1
        break
      fi
    done
    if [ "${found}" = 0 ]; then
      echo "FAIL: ${target} links unexpected API group package ${pkg}."
      echo "      If intentional, add it to allowed_api_packages in hack/verify-slimclient.sh."
      exit_code=1
    fi
  done <<<"${api_packages}"
done

if [ "${exit_code}" = 0 ]; then
  echo "slimclient dependency check passed."
fi
exit "${exit_code}"
