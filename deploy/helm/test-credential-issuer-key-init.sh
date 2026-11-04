#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Execute the exact rendered init script against disposable local paths. This
# needs no cluster, network, image build, Rust compilation, or real secret.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
chart="${root}/deploy/helm/openshell-credential-issuer"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
helm template issuer "${chart}" -f "${chart}/ci/values-test.yaml" >"${work}/render.yaml"
yq e -r 'select(.kind == "Deployment") | .spec.template.spec.initContainers[] | select(.name == "prepare-key") | .args[0]' "${work}/render.yaml" \
  | sed "s|/key-source/|${work}/source/|g; s|/key-runtime/|${work}/runtime/|g" >"${work}/init.sh"
mkdir "${work}/source" "${work}/runtime"
printf '%032d' 0 >"${work}/source/key"
chmod 0440 "${work}/source/key"
/bin/sh -e "${work}/init.sh"
cmp "${work}/source/key" "${work}/runtime/key"
[[ "$(stat -c %a "${work}/runtime/key")" == 600 ]]
[[ "$(stat -c %a "${work}/source/key")" == 440 ]]
# Absent or malformed source must not create or replace a runtime key.
chmod 0600 "${work}/source/key"
printf short >"${work}/source/key"
if /bin/sh -e "${work}/init.sh" >"${work}/error" 2>&1; then
  echo "FAIL: malformed KEK source was accepted" >&2; exit 1
fi
[[ "$(wc -c <"${work}/runtime/key" | tr -d '[:space:]')" == 32 ]]
mv "${work}/source/key" "${work}/source/missing-key"
if /bin/sh -e "${work}/init.sh" >"${work}/error" 2>&1; then
  echo "FAIL: missing KEK source was accepted" >&2; exit 1
fi
echo "rendered issuer KEK init preserves source, stages 0600 copy, rejects missing/invalid input"
