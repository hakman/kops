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

# Optional: pass a substring to filter test directories by name
DIR_FILTER="${1:-}"

# Number of "terraform validate" runs to execute concurrently
PARALLEL="${PARALLEL:-8}"

# Holds one init'ed .terraform directory and lock file per unique provider set
SEED_ROOT="$(mktemp -d)"
trap 'rm -rf "${SEED_ROOT}"' EXIT

mkdir -p "${PROVIDER_CACHE}"

tf_docker() {
  local test_dir="$1"
  shift
  docker run --rm --network host -e "TF_PLUGIN_CACHE_DIR=${PROVIDER_CACHE}" -v "${PROVIDER_CACHE}:${PROVIDER_CACHE}" -v "${test_dir}":"${test_dir}" -w "${test_dir}" --entrypoint=/bin/terraform "hashicorp/terraform:${TF_TAG}" "$@"
}
export -f tf_docker
export PROVIDER_CACHE TF_TAG

# The test dirs only use a few unique provider sets, so run the expensive
# "terraform init" (registry round trips) once per set and reuse the resulting
# .terraform directory and lock file in every other dir with the same set.
# Seed inits run serially because concurrent writes to TF_PLUGIN_CACHE_DIR are
# not supported by Terraform; the parallel validate stage only reads the cache.
WORK=()
while IFS= read -r -d '' -u 3 test_dir; do
  [ -f "${test_dir}/kubernetes.tf" ] || [ -f "${test_dir}/kubernetes.tf.json" ] || continue

  if [ -n "${DIR_FILTER}" ] && [[ "$(basename "${test_dir}")" != *"${DIR_FILTER}"* ]]; then
    continue
  fi

  key="$(grep -h '"source"' "${test_dir}"/kubernetes.tf* | grep -o '"[a-z0-9-]*/[a-z0-9-]*"' | sort -u | tr -cd 'a-z0-9\n' | paste -sd- -)"
  seed_dir="${SEED_ROOT}/${key}"
  if [ ! -d "${seed_dir}" ]; then
    echo "Initializing providers for ${key} (in ${test_dir})"
    rm -rf "${test_dir}/.terraform" "${test_dir}/.terraform.lock.hcl"
    tf_docker "${test_dir}" init -upgrade -input=false >/dev/null
    mkdir -p "${seed_dir}"
    mv "${test_dir}/.terraform" "${seed_dir}/terraform"
    mv "${test_dir}/.terraform.lock.hcl" "${seed_dir}/terraform.lock.hcl"
  fi
  WORK+=("${test_dir}" "${seed_dir}")
done 3< <(find "${KOPS_ROOT}/tests/integration/update_cluster" -maxdepth 1 -type d -print0)

validate_one() {
  local test_dir="$1"
  local seed_dir="$2"
  local rc=0
  local output

  if grep -qr "arn:aws:" "${test_dir}"; then
    echo "ARN reference uses hardcoded partition in ${test_dir}"
    rc=1
  fi
  if grep -qr "arn::" "${test_dir}"; then
    echo "ARN reference is missing partition in ${test_dir}"
    rc=1
  fi

  rm -rf "${test_dir}/.terraform" "${test_dir}/.terraform.lock.hcl"
  cp -R "${seed_dir}/terraform" "${test_dir}/.terraform"
  cp "${seed_dir}/terraform.lock.hcl" "${test_dir}/.terraform.lock.hcl"
  if output="$(tf_docker "${test_dir}" validate -no-color 2>&1)"; then
    echo "${test_dir}: OK"
  else
    echo "${test_dir}: FAILED"
    echo "${output}"
    rc=1
  fi

  return ${rc}
}
export -f validate_one

RC=0
if [ "${#WORK[@]}" -gt 0 ]; then
  printf '%s\n' "${WORK[@]}" | xargs -n2 -P "${PARALLEL}" bash -c 'validate_one "$@"' _ || RC=1
fi

if [ $RC != 0 ]; then
  echo -e "\nTerraform validation failed\n"
  exit $RC
else
  echo -e "\nTerraform validation succeeded\n"
fi
