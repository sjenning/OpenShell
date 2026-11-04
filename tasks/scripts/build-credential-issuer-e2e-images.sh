#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Build matching native candidate images for the clean two-cluster deployment
# lane. Serialize all Rust/image work: no task dependency fan-out or publishing.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
cd "${ROOT}"
source "${SCRIPT_DIR}/container-engine.sh"
source "${SCRIPT_DIR}/build-env.sh"
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; triple=x86_64-unknown-linux-gnu ;;
  aarch64|arm64) arch=arm64; triple=aarch64-unknown-linux-gnu ;;
  *) echo 'Error: credential issuer image E2E supports native amd64/arm64 only' >&2; exit 2 ;;
esac
if [[ -n "${DOCKER_PLATFORM:-}" && "${DOCKER_PLATFORM}" != "linux/${arch}" ]]; then
  echo 'Error: clean issuer E2E images must match the native cluster architecture' >&2; exit 2
fi
export DOCKER_PLATFORM="linux/${arch}" IMAGE_TAG="${IMAGE_TAG:-dev}"
# Loading into kind is a separate explicit test-fixture step. Never push here.
export DOCKER_PUSH=0
if [[ -n "${DOCKER_OUTPUT:-}" ]]; then
  echo 'Error: unset DOCKER_OUTPUT; issuer E2E requires locally loaded images' >&2; exit 2
fi
for component in gateway credential-issuer sandbox supervisor; do
  "${SCRIPT_DIR}/docker-build-image.sh" "${component}"
done
ensure_build_nofile_limit
build_target="${triple}.2.28"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
mise x -- rustup target add "${triple}"
eval "$("${SCRIPT_DIR}/setup-zig-cc-wrapper.sh" "${build_target}" "${build_target}" "${work}/zig-wrapper")"
CARGO_INCREMENTAL=0 mise x -- cargo zigbuild --locked --release --target "${build_target}" \
  --manifest-path tests/suites/features/Cargo.toml \
  --package openshell-test-feature-credential-issuer --bin credential-issuer-e2e-fixture
output="$(mise x -- cargo metadata --no-deps --format-version=1 --manifest-path tests/suites/features/Cargo.toml | jq -er '.target_directory')"
binary="${output}/${triple}/release/credential-issuer-e2e-fixture"
"${SCRIPT_DIR}/verify-glibc-symbols.sh" 2.28 "${binary}"
install -m 0755 "${binary}" "${work}/credential-issuer-e2e-fixture"
fixture_image="${OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE:-openshell/credential-issuer-e2e-fixture:${IMAGE_TAG}}"
ce_build --platform "linux/${arch}" --provenance=false \
  --file "${ROOT}/tests/suites/features/credential-issuer/Dockerfile.fixture" \
  --tag "${fixture_image}" --load "${work}"
printf 'Built matching local issuer E2E images; fixture image: %s\n' "${fixture_image}"
