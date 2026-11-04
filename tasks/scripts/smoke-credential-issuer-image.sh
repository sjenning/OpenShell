#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"
IMAGE="${ISSUER_IMAGE:-openshell/credential-issuer:${IMAGE_TAG:-dev}}"
if ! ce image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "Error: issuer image is not available locally: ${IMAGE}. Run mise run docker:build:credential-issuer first." >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cp "${ROOT}/deploy/helm/openshell-credential-issuer/examples/issuer.toml" "${work}/issuer.toml"
# Example has no secret contents. Permit UID 1000 to read this smoke-only bind.
chmod 0755 "${work}"
chmod 0444 "${work}/issuer.toml"
ce run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "${IMAGE}" --version \
  | grep -q '^openshell-credential-issuer '
ce run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "${work}:/config:ro,Z" "${IMAGE}" --config /config/issuer.toml --check-config
# A gateway-config path is not an accepted startup escape hatch.
if ce run --rm --network none --read-only "${IMAGE}" --bind-address 0.0.0.0 --port 8080 >"${work}/error" 2>&1; then
  echo "FAIL: issuer image accepted gateway listener arguments" >&2; exit 1
fi
sed 's/\["default"\]/["*"]/' "${work}/issuer.toml" >"${work}/invalid.toml"
chmod 0444 "${work}/invalid.toml"
if ce run --rm --network none --read-only -v "${work}:/config:ro,Z" "${IMAGE}" \
  --config /config/invalid.toml --check-config >"${work}/error" 2>&1; then
  echo "FAIL: issuer image accepted wildcard workspace scope" >&2; exit 1
fi
# Inspect the built runtime, not only the Dockerfile.
ce image inspect "${IMAGE}" --format '{{.Config.User}}' | grep -qx '1000:1000'
ports="$(ce image inspect "${IMAGE}" --format '{{json .Config.ExposedPorts}}')"
[[ "${ports}" == '{"8443/tcp":{}}' ]] || { echo "FAIL: unexpected issuer exposed ports: ${ports}" >&2; exit 1; }
echo "issuer image version, no-network configuration, identity scope, UID, and listener smoke checks passed"
