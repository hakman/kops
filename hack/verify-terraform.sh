#!/usr/bin/env bash

# Copyright 2020 The Kubernetes Authors.
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

set -o errexit
set -o nounset
set -o pipefail

. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Terraform versions
TF_TAG=1.14.8

PROVIDER_CACHE="${KOPS_ROOT}/.cache/terraform"
FIXTURES="${KOPS_ROOT}/tests/integration/update_cluster"

# Number of "terraform validate" runs to execute concurrently
PARALLEL="${PARALLEL:-8}"

tf_docker() {
  local test_dir="$1"
  shift
  docker run --rm \
    --network host \
    -e "TF_PLUGIN_CACHE_DIR=${PROVIDER_CACHE}" \
    -v "${PROVIDER_CACHE}:${PROVIDER_CACHE}" \
    -v "${test_dir}:${test_dir}" \
    -w "${test_dir}" \
    --entrypoint /bin/terraform \
    "hashicorp/terraform:${TF_TAG}" \
    "$@"
}

# Identifier for the exact provider requirements of a test dir, e.g.
# "hashicorpaws-hashicorpgoogle-2381116941". Dirs may share an init'ed
# .terraform only when both provider sources and version constraints match,
# so the version constraints are folded in as a checksum.
provider_key() {
  local requirements
  requirements="$(grep -hE '"(source|version)"' "$1"/kubernetes.tf* | tr -s ' ' | sort -u)"
  printf '%s-%s' \
    "$(grep -o '"[a-z0-9-]*/[a-z0-9-]*"' <<<"${requirements}" | sort -u | tr -cd 'a-z0-9\n' | paste -sd- -)" \
    "$(cksum <<<"${requirements}" | cut -d' ' -f1)"
}

validate_one() {
  local test_dir="$1"
  local seed_dir="$2"
  local output

  cp -R "${seed_dir}/.terraform" "${test_dir}/.terraform"
  cp "${seed_dir}/.terraform.lock.hcl" "${test_dir}/"
  if output="$(tf_docker "${test_dir}" validate -no-color 2>&1)"; then
    echo "${test_dir}: OK"
  else
    echo "${test_dir}: FAILED"
    printf '%s\n' "${output}"
    return 1
  fi
}

# Worker mode, used by the xargs fan-out below.
if [ "${1:-}" = "--validate-one" ]; then
  # GNU xargs invokes the command once even when there is no input at all.
  [ "$#" -eq 3 ] || exit 0
  validate_one "$3" "$2/$(provider_key "$3")"
  exit
fi

# Optional: pass a substring to filter test directories by name
DIR_FILTER="${1:-}"

# Holds one init'ed .terraform directory and lock file per unique provider set
SEED_ROOT="$(mktemp -d)"
kube::util::trap_add 'rm -rf "${SEED_ROOT}"' EXIT

mkdir -p "${PROVIDER_CACHE}"

RC=0

# Enumerate the test dirs, run the static ARN checks, and run the expensive
# "terraform init" (registry round trips) once per unique provider set,
# stashing the resulting .terraform directory and lock file for reuse by every
# dir with the same set. All seed inits must finish before any validate
# starts: "init -upgrade" rewrites provider binaries in TF_PLUGIN_CACHE_DIR,
# which fails with "text file busy" if a concurrent validate is executing them.
TEST_DIRS=()
for test_dir in "${FIXTURES}"/*/; do
  test_dir="${test_dir%/}"
  [ -f "${test_dir}/kubernetes.tf" ] || [ -f "${test_dir}/kubernetes.tf.json" ] || continue
  [[ -z "${DIR_FILTER}" || "$(basename "${test_dir}")" == *"${DIR_FILTER}"* ]] || continue

  rm -rf "${test_dir}/.terraform" "${test_dir}/.terraform.lock.hcl"

  if grep -qr "arn:aws:" "${test_dir}"; then
    echo "ARN reference uses hardcoded partition in ${test_dir}"
    RC=1
  fi
  if grep -qr "arn::" "${test_dir}"; then
    echo "ARN reference is missing partition in ${test_dir}"
    RC=1
  fi

  key="$(provider_key "${test_dir}")"
  seed_dir="${SEED_ROOT}/${key}"
  if [ ! -d "${seed_dir}" ]; then
    echo "Initializing providers for ${key} (in ${test_dir})"
    tf_docker "${test_dir}" init -upgrade -input=false >/dev/null
    mkdir -p "${seed_dir}"
    mv "${test_dir}/.terraform" "${test_dir}/.terraform.lock.hcl" "${seed_dir}/"
  fi

  TEST_DIRS+=("${test_dir}")
done

if [ "${#TEST_DIRS[@]}" -gt 0 ]; then
  printf '%s\0' "${TEST_DIRS[@]}" |
    xargs -0 -n1 -P "${PARALLEL}" "${KOPS_ROOT}/hack/verify-terraform.sh" --validate-one "${SEED_ROOT}" || RC=1
fi

if [ $RC != 0 ]; then
  echo -e "\nTerraform validation failed\n"
  exit $RC
else
  echo -e "\nTerraform validation succeeded\n"
fi
