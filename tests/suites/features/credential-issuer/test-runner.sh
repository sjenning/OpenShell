#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Pure shell safety regression tests. No real kubectl, Helm, Docker or Cargo.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
RUNNER="${ROOT}/tasks/scripts/test-credential-issuer-e2e.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "${work}/bin" "${work}/home/.kube"
touch "${work}/kubeconfig" "${work}/home/.kube/config"
cat >"${work}/bin/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_LOG"
context=''
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --kubeconfig) shift 2 ;;
    --context) context="$2"; shift 2 ;;
    --request-timeout=*) shift ;;
    *) break ;;
  esac
done
case "$*" in
  'config current-context') echo selected ;;
  'get namespace kube-system -o jsonpath={.metadata.uid}')
    case "$context/$MOCK_SCENARIO" in
      selected/unreachable) exit 1 ;;
      gateway/selected-alias) echo uid-selected ;;
      issuer/same-physical-cluster) echo uid-gateway ;;
      selected/*) echo uid-selected ;;
      gateway/*) echo uid-gateway ;;
      issuer/*) echo uid-issuer ;;
      *) echo 'unexpected context' >&2; exit 90 ;;
    esac ;;
  'get namespace issuer-e2e-gateway --ignore-not-found -o name')
    [[ "$MOCK_SCENARIO" != existing-namespace ]] || echo namespace/issuer-e2e-gateway ;;
  'get namespace issuer-e2e-security --ignore-not-found -o name') ;;
  'get crd sandboxes.agents.x-k8s.io') echo sandboxes.agents.x-k8s.io ;;
  *) echo "Unexpected or mutating kubectl call: $*" >&2; exit 91 ;;
esac
SH
chmod +x "${work}/bin/kubectl"
for command in helm openssl jq; do printf '#!/bin/sh\nexit 92\n' >"${work}/bin/${command}"; chmod +x "${work}/bin/${command}"; done
export PATH="${work}/bin:${PATH}" HOME="${work}/home" KUBECONFIG="${work}/kubeconfig"
export OPENSHELL_BIN=/bin/true
export OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE=fixture/gateway:candidate
export OPENSHELL_ISSUER_E2E_SUPERVISOR_IMAGE=fixture/supervisor:candidate
export OPENSHELL_ISSUER_E2E_SANDBOX_IMAGE=fixture/sandbox:candidate
export OPENSHELL_ISSUER_E2E_ISSUER_IMAGE=fixture/issuer:candidate
export OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE=fixture/minter:candidate
export OPENSHELL_ISSUER_E2E_KUBECONFIG="${work}/kubeconfig"
export OPENSHELL_ISSUER_E2E_GATEWAY_CONTEXT=gateway OPENSHELL_ISSUER_E2E_ISSUER_CONTEXT=issuer
export OPENSHELL_ISSUER_E2E_GATEWAY_NAMESPACE=issuer-e2e-gateway OPENSHELL_ISSUER_E2E_ISSUER_NAMESPACE=issuer-e2e-security
export OPENSHELL_ISSUER_E2E_ISSUER_ADDRESS=172.18.0.4 OPENSHELL_ISSUER_E2E_RESULTS="${work}/results"
export MOCK_LOG="${work}/kubectl.log" MOCK_SCENARIO=valid
run() { : >"$MOCK_LOG"; bash "$RUNNER" --preflight >"${work}/output" 2>&1; }
reject() {
  local expected="$1"
  if run; then echo "FAIL: accepted unsafe preflight: $MOCK_SCENARIO" >&2; cat "${work}/output"; exit 1; fi
  grep -q "$expected" "${work}/output" || { cat "${work}/output"; exit 1; }
  if grep -Eq '\b(create|apply|patch|scale|delete|install|use-context|set-context)\b' "$MOCK_LOG"; then
    echo 'FAIL: rejected preflight mutated a cluster' >&2; cat "$MOCK_LOG"; exit 1
  fi
}
run
grep -q 'Read-only preflight passed' "${work}/output"
MOCK_SCENARIO=selected-alias; reject 'currently selected cluster'
MOCK_SCENARIO=same-physical-cluster; reject 'physically separate clusters'
MOCK_SCENARIO=existing-namespace; reject 'already exists'
MOCK_SCENARIO=unreachable; reject 'cannot identify selected cluster'
MOCK_SCENARIO=valid
OPENSHELL_ISSUER_E2E_ISSUER_CONTEXT=gateway reject 'contexts must be distinct'
OPENSHELL_ISSUER_E2E_GATEWAY_NAMESPACE=openshell reject 'fresh namespaces must use'
OPENSHELL_ISSUER_E2E_KUBECONFIG='' reject 'KUBECONFIG is required'
OPENSHELL_ISSUER_E2E_ISSUER_PORT=8443 reject 'Kubernetes NodePorts'
OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE=fixture/gateway reject 'explicit image tag/digest required'
OPENSHELL_ISSUER_E2E_DELIVERY_MODE=unknown reject 'DELIVERY_MODE must be'
OPENSHELL_ISSUER_E2E_ISSUER_ADDRESS=8.8.8.8 reject 'private routing'
OPENSHELL_ISSUER_E2E_ISSUER_ADDRESS=172.18.0.999 reject 'canonical IPv4'
# A failed kind create can leave containers/network state behind even when its
# kubeconfig write or readiness wait fails. Emulate that partial allocation on
# either create, without ever reaching a real cluster, container engine or build.
mkdir -p "${work}/tmp"
export MOCK_KIND_STATE="${work}/kind-state" MOCK_KIND_LOG="${work}/kind.log"
export MOCK_DOCKER_LOG="${work}/docker.log" MOCK_CARGO_LOG="${work}/cargo.log"
export MOCK_PRIVATE_TMP="${work}/tmp"
cat >"${work}/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
case "$*" in
  info|'image inspect fixture/'*) exit 0 ;;
  *) echo "Unexpected docker invocation: $*" >&2; exit 93 ;;
esac
SH
cat >"${work}/bin/cargo" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_CARGO_LOG"
echo 'Cargo must never execute in the fake-kind cleanup regression' >&2
exit 94
SH
# The runner deliberately supports kind NodeIP routing only on Linux. Make the
# shell regression portable without weakening that production runtime check.
cat >"${work}/bin/uname" <<'SH'
#!/usr/bin/env bash
[[ "$*" == -s ]] || exit 95
echo Linux
SH
cat >"${work}/bin/kind" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
action="${1:-}"; subcommand="${2:-}"; shift 2
name=''; explicit_config=''
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --name) name="$2"; shift 2 ;;
    --kubeconfig) explicit_config="$2"; shift 2 ;;
    --config|--wait) shift 2 ;;
    *) echo "Unexpected kind argument: $1" >&2; exit 96 ;;
  esac
done
[[ "$subcommand" == cluster && "$action" =~ ^(create|delete)$ ]] || exit 96
[[ "$name" =~ ^issuer-e2e-(gw|security)-[0-9]{8}t[0-9]{6}-[0-9]+$ ]] || {
  echo 'Refusing operation on a non-generated/preexisting cluster' >&2; exit 96;
}
[[ "${KUBECONFIG:-}" == "$MOCK_PRIVATE_TMP"/openshell-issuer-e2e.*/kubeconfig ]] || {
  echo 'kind did not receive an isolated temporary kubeconfig' >&2; exit 96;
}
[[ "${KUBECONFIG:-}" != "$OPENSHELL_ISSUER_E2E_KUBECONFIG" ]] || exit 96
printf '%s\t%s\t%s\t%s\n' "$action" "$name" "$KUBECONFIG" "$explicit_config" >> "$MOCK_KIND_LOG"
case "$action" in
  create)
    [[ "$explicit_config" == "$KUBECONFIG" && -d "${KUBECONFIG%/*}" ]] || exit 96
    # Pretend containers already exist and kubeconfig has been partially written.
    [[ ! -e "$MOCK_KIND_STATE/$name" ]] || exit 96
    mkdir "$MOCK_KIND_STATE/$name"
    printf 'kind-private-config:%s\n' "$name" > "$KUBECONFIG"
    count="$(cat "$MOCK_KIND_STATE/create-count")"
    count=$((count + 1))
    echo "$count" > "$MOCK_KIND_STATE/create-count"
    if [[ "$count" == "$MOCK_KIND_FAIL_CREATE" ]]; then
      echo "injected partial kind create failure $count" >&2
      exit "$((40 + count))"
    fi ;;
  delete)
    [[ -d "$MOCK_KIND_STATE/$name" ]] || exit 96
    rmdir "$MOCK_KIND_STATE/$name" ;;
esac
SH
chmod +x "${work}/bin/docker" "${work}/bin/cargo" "${work}/bin/uname" "${work}/bin/kind"

kind_partial_failure() {
  local ordinal="$1" code=0 private_config
  : >"$MOCK_LOG"; : >"$MOCK_KIND_LOG"; : >"$MOCK_DOCKER_LOG"; : >"$MOCK_CARGO_LOG"
  mkdir -p "$MOCK_KIND_STATE/preexisting-selected" "$MOCK_KIND_STATE/preexisting-unselected"
  echo 0 > "$MOCK_KIND_STATE/create-count"
  printf 'ambient-selected-config\n' > "$OPENSHELL_ISSUER_E2E_KUBECONFIG"
  printf 'normal-user-selected-config\n' > "${HOME}/.kube/config"
  cp "$OPENSHELL_ISSUER_E2E_KUBECONFIG" "${work}/ambient-before"
  cp "${HOME}/.kube/config" "${work}/normal-before"
  TMPDIR="$MOCK_PRIVATE_TMP" MOCK_KIND_FAIL_CREATE="$ordinal" \
    bash "$RUNNER" --kind >"${work}/kind-output" 2>&1 || code=$?
  if [[ "$code" != "$((40 + ordinal))" ]]; then
    echo "FAIL: partial kind create $ordinal did not preserve its failure status" >&2
    cat "${work}/kind-output"; exit 1
  fi
  grep -q "injected partial kind create failure $ordinal" "${work}/kind-output"
  [[ "$(awk -F '\t' '$1 == "create" { count++ } END { print count+0 }' "$MOCK_KIND_LOG")" == "$ordinal" ]]
  [[ "$(awk -F '\t' '$1 == "delete" { count++ } END { print count+0 }' "$MOCK_KIND_LOG")" == "$ordinal" ]]
  awk -F '\t' '$1 == "create" { print $2 }' "$MOCK_KIND_LOG" | sort >"${work}/created-clusters"
  awk -F '\t' '$1 == "delete" { print $2 }' "$MOCK_KIND_LOG" | sort >"${work}/deleted-clusters"
  cmp "${work}/created-clusters" "${work}/deleted-clusters"
  [[ "$(sort -u "${work}/created-clusters" | wc -l)" -eq "$ordinal" ]]
  # Every create/delete must use the same private config. It must be gone after
  # cleanup, while both operator configs and both preexisting clusters survive.
  [[ "$(cut -f 3 "$MOCK_KIND_LOG" | sort -u | wc -l)" -eq 1 ]]
  private_config="$(cut -f 3 "$MOCK_KIND_LOG" | head -1)"
  [[ ! -e "${private_config%/*}" ]]
  cmp "$OPENSHELL_ISSUER_E2E_KUBECONFIG" "${work}/ambient-before"
  cmp "${HOME}/.kube/config" "${work}/normal-before"
  [[ -d "$MOCK_KIND_STATE/preexisting-selected" && -d "$MOCK_KIND_STATE/preexisting-unselected" ]]
  [[ "$(find "$MOCK_KIND_STATE" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 2 ]]
  [[ ! -s "$MOCK_CARGO_LOG" ]]
  [[ "$(wc -l < "$MOCK_DOCKER_LOG")" -eq 6 ]]
  if grep -Eq '\b(create|apply|patch|scale|delete|install|use-context|set-context)\b' "$MOCK_LOG"; then
    echo 'FAIL: partial kind cleanup mutated a selected Kubernetes context' >&2
    cat "$MOCK_LOG"; exit 1
  fi
}
kind_partial_failure 1
kind_partial_failure 2

echo 'issuer E2E runner: 13 isolation/input and 2 partial-kind cleanup checks passed; no real cluster, container, or Cargo access'
