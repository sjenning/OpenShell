#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Own only fresh namespaces or two explicitly requested disposable kind clusters.
# Never select a context, merge kubeconfig, or fall back to kubectl's context.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${ROOT}/tests/suites/features/credential-issuer"
mode="${1:---external}"
fail() { echo "credential-issuer E2E: $*" >&2; exit 2; }
need() { command -v "$1" >/dev/null || fail "missing $1; see ${SUITE}/README.md"; }
required() { [[ -n "${!1:-}" ]] || fail "$1 is required; see ${SUITE}/README.md (no tests were skipped)"; }
case "$mode" in
  --help|-h)
    echo 'Usage: mise run e2e:credential-issuer | mise run e2e:credential-issuer:kind'
    echo 'Read tests/suites/features/credential-issuer/README.md before using external contexts.'
    exit 0 ;;
  --kind|--external|--preflight) ;;
  *) fail "unknown mode $mode" ;;
esac

need kubectl; need helm; need openssl; need jq
[[ "$mode" == --preflight ]] || need cargo
# Explicit images prevent accidentally testing unrelated published latest tags.
for key in OPENSHELL_BIN OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE OPENSHELL_ISSUER_E2E_SUPERVISOR_IMAGE \
  OPENSHELL_ISSUER_E2E_SANDBOX_IMAGE OPENSHELL_ISSUER_E2E_ISSUER_IMAGE OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE; do
  required "$key"
done
[[ -x "$OPENSHELL_BIN" ]] || fail 'OPENSHELL_BIN must name an executable candidate CLI'
for key in OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE OPENSHELL_ISSUER_E2E_SUPERVISOR_IMAGE \
  OPENSHELL_ISSUER_E2E_SANDBOX_IMAGE OPENSHELL_ISSUER_E2E_ISSUER_IMAGE OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE; do
  [[ "${!key}" =~ ^[a-zA-Z0-9./_:@-]+$ ]] || fail "invalid image reference in $key"
  image="${!key}"
  [[ "$image" == *@sha256:* || "${image##*/}" == *:* ]] || fail "explicit image tag/digest required in $key"
done

# Record every ambient selected cluster before any private kubeconfig is made.
# Compare physical kube-system UIDs, not context names (aliases are not isolation).
forbidden_uids=()
remember_current_cluster() {
  local config="$1" context uid
  [[ -f "$config" ]] || return 0
  context="$(kubectl --kubeconfig "$config" config current-context 2>/dev/null || true)"
  [[ -n "$context" ]] || return 0
  uid="$(kubectl --kubeconfig "$config" --context "$context" --request-timeout=15s get namespace kube-system -o jsonpath='{.metadata.uid}')" \
    || fail "cannot identify selected cluster in $config; refusing to mutate any cluster"
  [[ -n "$uid" ]] || fail 'selected cluster has no kube-system UID'
  forbidden_uids+=("$uid")
}
# A mise invocation may override KUBECONFIG with the checkout-local path. Also
# protect the normal user kubeconfig, and the explicitly supplied config's selection.
remember_current_cluster "${HOME}/.kube/config"
if [[ -n "${KUBECONFIG:-}" ]]; then
  IFS=: read -r -a ambient_configs <<< "$KUBECONFIG"
  for config in "${ambient_configs[@]}"; do remember_current_cluster "$config"; done
fi
if [[ -n "${OPENSHELL_ISSUER_E2E_KUBECONFIG:-}" ]]; then
  remember_current_cluster "$OPENSHELL_ISSUER_E2E_KUBECONFIG"
fi

run="$(date -u +%Y%m%dT%H%M%S)-${RANDOM}"
work="$(mktemp -d "${TMPDIR:-/tmp}/openshell-issuer-e2e.XXXXXX")"
chmod 700 "$work"
results="${OPENSHELL_ISSUER_E2E_RESULTS:-${ROOT}/results/credential-issuer}/${run}"
mkdir -p "$results"; chmod 700 "$results"
created_gateway_ns=0; created_issuer_ns=0
created_gateway_cluster=0; created_issuer_cluster=0
forward_pid=""
gateway_context="${OPENSHELL_ISSUER_E2E_GATEWAY_CONTEXT:-}"
issuer_context="${OPENSHELL_ISSUER_E2E_ISSUER_CONTEXT:-}"
gateway_ns="${OPENSHELL_ISSUER_E2E_GATEWAY_NAMESPACE:-}"
issuer_ns="${OPENSHELL_ISSUER_E2E_ISSUER_NAMESPACE:-}"
kubeconfig="${OPENSHELL_ISSUER_E2E_KUBECONFIG:-}"
kctl() { local context="$1"; shift; kubectl --kubeconfig "$kubeconfig" --context "$context" --request-timeout=30s "$@"; }
hctl() { local context="$1"; shift; helm --kubeconfig "$kubeconfig" --kube-context "$context" "$@"; }
collect() {
  local context="$1" ns="$2" label="$3"
  kctl "$context" -n "$ns" get pods -o wide >"${results}/${label}-pods.txt" 2>&1 || true
  kctl "$context" -n "$ns" get events --sort-by=.lastTimestamp >"${results}/${label}-events.txt" 2>&1 || true
  # Never collect Secrets, TOML, ConfigMaps, describe output/env, or mounted files.
  kctl "$context" -n "$ns" logs -l app.kubernetes.io/instance="${label}" --all-containers --prefix --tail=300 \
    >"${results}/${label}.log" 2>&1 || true
}
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  set +e
  [[ "$created_gateway_ns" == 0 ]] || collect "$gateway_context" "$gateway_ns" gateway
  [[ "$created_issuer_ns" == 0 ]] || collect "$issuer_context" "$issuer_ns" issuer
  [[ -z "$forward_pid" ]] || { kill "$forward_pid" 2>/dev/null; wait "$forward_pid" 2>/dev/null; }
  # Namespaces must have been created successfully by this invocation. Never
  # delete/reuse a pre-existing namespace, release, kubeconfig, or cluster.
  if [[ "$created_gateway_ns" == 1 ]]; then
    hctl "$gateway_context" uninstall gateway -n "$gateway_ns" --ignore-not-found --wait --timeout 120s >"${results}/gateway-cleanup.log" 2>&1 || code=1
    kctl "$gateway_context" delete namespace "$gateway_ns" --wait=true --timeout=180s >>"${results}/gateway-cleanup.log" 2>&1 || code=1
  fi
  if [[ "$created_issuer_ns" == 1 ]]; then
    hctl "$issuer_context" uninstall issuer -n "$issuer_ns" --ignore-not-found --wait --timeout 120s >"${results}/issuer-cleanup.log" 2>&1 || code=1
    kctl "$issuer_context" delete namespace "$issuer_ns" --wait=true --timeout=180s >>"${results}/issuer-cleanup.log" 2>&1 || code=1
  fi
  if [[ "$created_gateway_cluster" == 1 ]]; then
    kind delete cluster --name "$gateway_cluster" >"${results}/gateway-kind-cleanup.log" 2>&1 || code=1
  fi
  if [[ "$created_issuer_cluster" == 1 ]]; then
    kind delete cluster --name "$issuer_cluster" >"${results}/issuer-kind-cleanup.log" 2>&1 || code=1
  fi
  # This path was allocated by mktemp above and never supplied by the caller.
  rm -rf "$work"
  printf 'Exit status: %s\nEvidence: %s\n' "$code" "$results"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$mode" == --kind ]]; then
  [[ "$(uname -s)" == Linux ]] || fail 'local kind cross-cluster NodeIP routing requires Linux; use explicit routed contexts on other hosts'
  need kind; need docker
  # No implicit image builds or pulls: the owner serializes candidate builds.
  docker info >/dev/null
  for key in OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE OPENSHELL_ISSUER_E2E_SUPERVISOR_IMAGE \
    OPENSHELL_ISSUER_E2E_SANDBOX_IMAGE OPENSHELL_ISSUER_E2E_ISSUER_IMAGE OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE; do
    docker image inspect "${!key}" >/dev/null || fail "candidate image ${!key} is not local; build it first"
  done
  gateway_cluster="issuer-e2e-gw-${run,,}"; issuer_cluster="issuer-e2e-security-${run,,}"
  # kind writes only this disposable kubeconfig; ~/.kube/config is untouched.
  kubeconfig="${work}/kubeconfig"
  export KUBECONFIG="$kubeconfig"
  gateway_context="kind-${gateway_cluster}"; issuer_context="kind-${issuer_cluster}"
  gateway_ns="issuer-e2e-gateway"; issuer_ns="issuer-e2e-security"
  cat >"${work}/kind-gateway.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/16
YAML
  cat >"${work}/kind-issuer.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: 10.245.0.0/16
  serviceSubnet: 10.97.0.0/16
YAML
  # Claim only these freshly generated names before creation so partial kind
  # failures still run cleanup. Never use the operator's selected kubeconfig.
  created_gateway_cluster=1
  kind create cluster --name "$gateway_cluster" --kubeconfig "$kubeconfig" --config "${work}/kind-gateway.yaml" --wait 120s
  created_issuer_cluster=1
  kind create cluster --name "$issuer_cluster" --kubeconfig "$kubeconfig" --config "${work}/kind-issuer.yaml" --wait 120s
  kind load docker-image --name "$gateway_cluster" "$OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE" "$OPENSHELL_ISSUER_E2E_SUPERVISOR_IMAGE" "$OPENSHELL_ISSUER_E2E_SANDBOX_IMAGE"
  kind load docker-image --name "$issuer_cluster" "$OPENSHELL_ISSUER_E2E_ISSUER_IMAGE" "$OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE"
  # Reuse the repository's pinned upstream controller install, only on our new cluster.
  bash "${ROOT}/e2e/support/install-agent-sandbox.sh" --kubeconfig "$kubeconfig" --context "$gateway_context"
  address="$(kctl "$issuer_context" get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
  issuer_port=30443; minter_port=30444; resource_port=30080
else
  for key in OPENSHELL_ISSUER_E2E_KUBECONFIG OPENSHELL_ISSUER_E2E_GATEWAY_CONTEXT \
    OPENSHELL_ISSUER_E2E_ISSUER_CONTEXT OPENSHELL_ISSUER_E2E_GATEWAY_NAMESPACE OPENSHELL_ISSUER_E2E_ISSUER_NAMESPACE \
    OPENSHELL_ISSUER_E2E_ISSUER_ADDRESS; do required "$key"; done
  [[ -f "$kubeconfig" && "$kubeconfig" != *:* ]] || fail 'supply exactly one explicit kubeconfig file'
  address="$OPENSHELL_ISSUER_E2E_ISSUER_ADDRESS"
  issuer_port="${OPENSHELL_ISSUER_E2E_ISSUER_PORT:-30443}"
  minter_port="${OPENSHELL_ISSUER_E2E_MINTER_PORT:-30444}"
  resource_port="${OPENSHELL_ISSUER_E2E_RESOURCE_PORT:-30080}"
fi
[[ "$gateway_context" != "$issuer_context" ]] || fail 'gateway and issuer contexts must be distinct'
for context in "$gateway_context" "$issuer_context"; do
  [[ "$context" =~ ^[a-zA-Z0-9_.:-]+$ ]] || fail 'context names may contain only letters, digits, dot, colon, underscore and hyphen'
done
[[ "${OPENSHELL_ISSUER_E2E_DELIVERY_MODE:-push}" =~ ^(push|poll)$ ]] || fail 'DELIVERY_MODE must be push or poll'
for ns in "$gateway_ns" "$issuer_ns"; do
  [[ "$ns" =~ ^issuer-e2e-[a-z0-9-]+$ && ${#ns} -le 63 ]] || fail 'fresh namespaces must use the issuer-e2e- prefix and be DNS labels'
done
[[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'ISSUER_ADDRESS must be the private, routed IPv4 address of an issuer-cluster node (not a URL)'
IFS=. read -r octet_a octet_b octet_c octet_d <<< "$address"
for octet in "$octet_a" "$octet_b" "$octet_c" "$octet_d"; do
  [[ "$octet" == "$((10#$octet))" && "$octet" -le 255 ]] || fail 'ISSUER_ADDRESS must be canonical IPv4'
done
if ! { [[ "$octet_a" == 10 ]] || [[ "$octet_a" == 172 && "$octet_b" -ge 16 && "$octet_b" -le 31 ]] \
  || [[ "$octet_a" == 192 && "$octet_b" == 168 ]] || [[ "$octet_a" == 100 && "$octet_b" -ge 64 && "$octet_b" -le 127 ]]; }; then
  fail 'ISSUER_ADDRESS must use RFC1918 or RFC6598 private routing; no public NodePort exposure'
fi
for port in "$issuer_port" "$minter_port" "$resource_port"; do
  [[ "$port" =~ ^[0-9]{5}$ && "$port" -ge 30000 && "$port" -le 32767 ]] || fail 'fixture ports must be Kubernetes NodePorts (30000..32767)'
done
[[ "$issuer_port" != "$minter_port" && "$issuer_port" != "$resource_port" && "$minter_port" != "$resource_port" ]] || fail 'fixture NodePorts must differ'
gateway_uid="$(kctl "$gateway_context" get namespace kube-system -o jsonpath='{.metadata.uid}')"
issuer_uid="$(kctl "$issuer_context" get namespace kube-system -o jsonpath='{.metadata.uid}')"
[[ -n "$gateway_uid" && -n "$issuer_uid" && "$gateway_uid" != "$issuer_uid" ]] || fail 'contexts must identify physically separate clusters (kube-system UID differs)'
for forbidden in "${forbidden_uids[@]}"; do
  [[ "$gateway_uid" != "$forbidden" && "$issuer_uid" != "$forbidden" ]] || fail 'refusing to mutate a currently selected cluster, including aliases'
done
for pair in "$gateway_context/$gateway_ns" "$issuer_context/$issuer_ns"; do
  context="${pair%/*}"; ns="${pair##*/}"
  [[ -z "$(kctl "$context" get namespace "$ns" --ignore-not-found -o name)" ]] || fail "namespace $ns already exists; refusing to reuse or alter it"
done
kctl "$gateway_context" get crd sandboxes.agents.x-k8s.io >/dev/null \
  || fail 'install the pinned Agent Sandbox prerequisite on the explicit gateway cluster first'
if [[ "$mode" == --preflight ]]; then
  echo 'Read-only preflight passed: two non-selected clusters, fresh namespaces, explicit candidate images.'
  exit 0
fi
umask 077
kctl "$gateway_context" create namespace "$gateway_ns"; created_gateway_ns=1
kctl "$issuer_context" create namespace "$issuer_ns"; created_issuer_ns=1
jq -n --arg run "$run" --arg gateway_context "$gateway_context" --arg issuer_context "$issuer_context" \
  --arg gateway_uid "$gateway_uid" --arg issuer_uid "$issuer_uid" --arg gateway_namespace "$gateway_ns" --arg issuer_namespace "$issuer_ns" \
  '{run:$run, topology:"separate-clusters",gateway_context:$gateway_context,issuer_context:$issuer_context,gateway_cluster_uid:$gateway_uid,issuer_cluster_uid:$issuer_uid,gateway_namespace:$gateway_namespace,issuer_namespace:$issuer_namespace}' >"${results}/topology.json"

# Dedicated ephemeral CA and role-distinct identities; never use the operator's PKI.
mkdir "${work}/pki"
pki="${work}/pki"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=issuer-e2e-ca \
  -keyout "${pki}/ca.key" -out "${pki}/ca.crt" >/dev/null 2>&1
cert() {
  local name="$1" usage="$2" sans="$3"
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${name}" -keyout "${pki}/${name}.key" -out "${pki}/${name}.csr" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$usage" "$sans" >"${pki}/${name}.ext"
  openssl x509 -req -days 2 -in "${pki}/${name}.csr" -CA "${pki}/ca.crt" -CAkey "${pki}/ca.key" \
    -CAcreateserial -extfile "${pki}/${name}.ext" -out "${pki}/${name}.crt" >/dev/null 2>&1
}
cert gateway clientAuth URI:spiffe://issuer-e2e.test/gateway/primary
cert other-gateway clientAuth URI:spiffe://issuer-e2e.test/gateway/other
cert unknown clientAuth URI:spiffe://issuer-e2e.test/gateway/unbound
cert issuer-client clientAuth URI:spiffe://issuer-e2e.test/issuer/security
cert issuer serverAuth "DNS:issuer.${issuer_ns}.svc.cluster.local,IP:${address}"
cert minter serverAuth "DNS:minter.${issuer_ns}.svc.cluster.local,IP:${address}"
openssl rand -out "${work}/key" 32

cat >"${work}/issuer.toml" <<EOF
[openshell.credential_issuer]
listen = "0.0.0.0:8443"
database_url = "sqlite:///var/lib/openshell-issuer/issuer.db?mode=rwc"
replicas = 1
key_encryption_key_path = "/etc/openshell-issuer/encryption/key"
tls_cert_path = "/etc/openshell-issuer/tls/tls.crt"
tls_key_path = "/etc/openshell-issuer/tls/tls.key"
tls_client_ca_path = "/etc/openshell-issuer/tls/client-ca.pem"
cache_ttl_seconds = 0
refresh_interval_seconds = 1
shutdown_timeout_seconds = 5
[openshell.credential_issuer.gateway_identities]
"spiffe://issuer-e2e.test/gateway/primary" = ["default"]
"spiffe://issuer-e2e.test/gateway/other" = ["default"]
[openshell.credential_issuer.minters.e2e]
endpoint = "https://minter.${issuer_ns}.svc.cluster.local:8443"
tls_ca_cert_path = "/etc/openshell-issuer/registrations/minter/ca.crt"
tls_client_cert_path = "/etc/openshell-issuer/registrations/minter/tls.crt"
tls_client_key_path = "/etc/openshell-issuer/registrations/minter/tls.key"
EOF
kctl "$issuer_context" -n "$issuer_ns" create secret generic issuer-config --from-file="issuer.toml=${work}/issuer.toml" >/dev/null
kctl "$issuer_context" -n "$issuer_ns" create secret generic issuer-tls --from-file="tls.crt=${pki}/issuer.crt" --from-file="tls.key=${pki}/issuer.key" --from-file="client-ca.pem=${pki}/ca.crt" >/dev/null
kctl "$issuer_context" -n "$issuer_ns" create secret generic issuer-kek --from-file="key=${work}/key" >/dev/null
kctl "$issuer_context" -n "$issuer_ns" create secret generic issuer-minter-client --from-file="tls.crt=${pki}/issuer-client.crt" --from-file="tls.key=${pki}/issuer-client.key" --from-file="ca.crt=${pki}/ca.crt" >/dev/null
kctl "$issuer_context" -n "$issuer_ns" create secret generic minter-tls --from-file="tls.crt=${pki}/minter.crt" --from-file="tls.key=${pki}/minter.key" --from-file="client-ca.pem=${pki}/ca.crt" >/dev/null
kctl "$gateway_context" -n "$gateway_ns" create secret generic gateway-issuer-client --from-file="tls.crt=${pki}/gateway.crt" --from-file="tls.key=${pki}/gateway.key" --from-file="ca.crt=${pki}/ca.crt" >/dev/null

cat >"${work}/fixture.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: minter}
spec:
  replicas: 1
  selector: {matchLabels: {app: issuer-e2e-minter}}
  template:
    metadata: {labels: {app: issuer-e2e-minter}}
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000}
      containers:
        - name: minter
          image: ${OPENSHELL_ISSUER_E2E_FIXTURE_IMAGE}
          imagePullPolicy: IfNotPresent
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          ports: [{containerPort: 8443, name: mtls}, {containerPort: 8080, name: resource}]
          readinessProbe: {httpGet: {path: /ready, port: resource}}
          volumeMounts: [{name: tls, mountPath: /fixture, readOnly: true}]
      volumes: [{name: tls, secret: {secretName: minter-tls, defaultMode: 288}}]
---
apiVersion: v1
kind: Service
metadata: {name: minter}
spec:
  type: NodePort
  selector: {app: issuer-e2e-minter}
  ports:
    - {name: mtls, port: 8443, targetPort: mtls, nodePort: ${minter_port}}
    - {name: resource, port: 8080, targetPort: resource, nodePort: ${resource_port}}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: issuer-data}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
EOF
kctl "$issuer_context" -n "$issuer_ns" apply -f "${work}/fixture.yaml" >/dev/null
kctl "$issuer_context" -n "$issuer_ns" rollout status deployment/minter --timeout=180s
# Full image references are split into repository/tag/digest without losing ports.
image_values() {
  local image="$1" prefix="$2" repository tag digest
  if [[ "$image" == *@* ]]; then repository="${image%@*}"; digest="${image#*@}"; tag="";
  elif [[ "${image##*/}" == *:* ]]; then repository="${image%:*}"; tag="${image##*:}"; digest="";
  else fail 'each candidate image must have an explicit tag or digest'; fi
  printf '%s:\n  repository: %s\n  tag: "%s"\n  digest: "%s"\n  pullPolicy: IfNotPresent\n' "$prefix" "$repository" "$tag" "$digest"
}
{
  image_values "$OPENSHELL_ISSUER_E2E_ISSUER_IMAGE" image
  cat <<EOF
fullnameOverride: issuer
config: {existingSecret: issuer-config, revision: e2e}
tls: {existingSecret: issuer-tls}
encryption: {existingSecret: issuer-kek}
database: {kind: sqlite, existingClaim: issuer-data}
terminationGracePeriodSeconds: 10
registrationSecrets: [{name: minter, secretName: issuer-minter-client}]
# NodePort preserves TLS end-to-end. The source may be SNATed by either cluster;
# this isolated namespace permits private routed CIDRs. Exact mTLS identity and
# workspace binding remain mandatory and are negatively tested. No public CIDR.
networkPolicy:
  ingressFrom:
    - {ipBlock: {cidr: 10.0.0.0/8}}
    - {ipBlock: {cidr: 172.16.0.0/12}}
    - {ipBlock: {cidr: 192.168.0.0/16}}
    - {ipBlock: {cidr: 100.64.0.0/10}}
EOF
} >"${work}/issuer-values.yaml"
hctl "$issuer_context" install issuer "${ROOT}/deploy/helm/openshell-credential-issuer" -n "$issuer_ns" -f "${work}/issuer-values.yaml" --wait --timeout 300s
# Add only a test-owned raw TCP cross-cluster route; the product chart remains private ClusterIP.
cat >"${work}/issuer-route.yaml" <<EOF
apiVersion: v1
kind: Service
metadata: {name: issuer-cross-cluster}
spec:
  type: NodePort
  selector: {app.kubernetes.io/instance: issuer, app.kubernetes.io/name: openshell-credential-issuer}
  ports: [{name: issuer-mtls, port: 8443, targetPort: issuer-mtls, nodePort: ${issuer_port}}]
EOF
kctl "$issuer_context" -n "$issuer_ns" apply -f "${work}/issuer-route.yaml" >/dev/null

# Use the maintained gateway chart, with only names/paths (never credential
# values) in its ConfigMap. Bootstrap TLS/JWT remain chart-owned local files.
{
  for component in gateway supervisor sandboxRuntime; do
    case "$component" in gateway) image="$OPENSHELL_ISSUER_E2E_GATEWAY_IMAGE" ;; supervisor) image="$OPENSHELL_ISSUER_E2E_SUPERVISOR_IMAGE" ;; sandboxRuntime) image="$OPENSHELL_ISSUER_E2E_SANDBOX_IMAGE" ;; esac
    echo "${component}:"
    image_values "$image" image | sed 's/^/  /'
  done
  cat <<EOF
fullnameOverride: gateway
global:
  image: {registry: ""}
server:
  disableTls: false
  telemetryEnabled: false
  dataStorageSize: 1Gi
  workspaceDefaultStorageSize: 1Gi
  extraVolumes: [{name: issuer-client, secret: {secretName: gateway-issuer-client}}]
  extraVolumeMounts: [{name: issuer-client, mountPath: /etc/issuer-client, readOnly: true}]
sandbox:
  image: {repository: nvcr.io/nvidia/base/ubuntu, tag: "24.04", pullPolicy: if_not_present}
gatewayConfig:
  openshell: {version: 2}
  openshell.gateway:
    config_delivery_mode: ${OPENSHELL_ISSUER_E2E_DELIVERY_MODE:-push}
  openshell.gateway.credential_issuer:
    name: e2e
    endpoint: https://${address}:${issuer_port}
    server_ca_path: /etc/issuer-client/ca.crt
    client_cert_path: /etc/issuer-client/tls.crt
    client_key_path: /etc/issuer-client/tls.key
    startup_timeout_seconds: 60
  openshell.drivers.kubernetes:
    image_pull_policy: if_not_present
    supervisor_topology: gateway
EOF
} >"${work}/gateway-values.yaml"
hctl "$gateway_context" install gateway "${ROOT}/deploy/helm/openshell" -n "$gateway_ns" -f "${work}/gateway-values.yaml" --wait --timeout 600s
# Extract only the dedicated test release's public-client identity.
mkdir -p "${work}/client-pki/client"
for pair in 'ca.crt:ca.crt' 'tls.crt:client/tls.crt' 'tls.key:client/tls.key'; do
  key="${pair%%:*}"; path="${pair#*:}"
  kctl "$gateway_context" -n "$gateway_ns" get secret openshell-client-tls -o "jsonpath={.data.${key//./\\.}}" | base64 -d >"${work}/client-pki/${path}"
done
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"
e2e_preserve_mise_dirs
export XDG_CONFIG_HOME="${work}/config" XDG_DATA_HOME="${work}/data"
# kubectl chooses a free loopback port. No host-wide listener or forwarding of mTLS terminators.
kctl "$gateway_context" -n "$gateway_ns" port-forward --address 127.0.0.1 svc/gateway :8080 >"${work}/forward.log" 2>&1 &
forward_pid=$!
for _ in $(seq 1 100); do
  grep -q 'Forwarding from 127.0.0.1:' "${work}/forward.log" && break
  kill -0 "$forward_pid" 2>/dev/null || fail 'gateway port-forward exited'
  sleep 0.1
done
port="$(sed -n 's/.*Forwarding from 127.0.0.1:\([0-9]*\) ->.*/\1/p' "${work}/forward.log" | head -1)"
[[ -n "$port" ]] || fail 'gateway port-forward did not become ready'
e2e_register_mtls_gateway "$XDG_CONFIG_HOME" issuer-e2e "https://127.0.0.1:${port}" "$port" "${work}/client-pki"
export OPENSHELL_GATEWAY=issuer-e2e OPENSHELL_GATEWAY_ENDPOINT="https://127.0.0.1:${port}" OPENSHELL_WORKSPACE=default
export OPENSHELL_ISSUER_E2E_TOPOLOGY=separate-clusters
export OPENSHELL_ISSUER_E2E_KUBECONFIG="$kubeconfig" OPENSHELL_ISSUER_E2E_ISSUER_CONTEXT="$issuer_context" OPENSHELL_ISSUER_E2E_ISSUER_NAMESPACE="$issuer_ns"
export OPENSHELL_ISSUER_E2E_PKI="$pki" OPENSHELL_ISSUER_E2E_RESOURCE_HOST="$address" OPENSHELL_ISSUER_E2E_RESOURCE_PORT="$resource_port"
export OPENSHELL_ISSUER_E2E_ISSUER_ENDPOINT="https://${address}:${issuer_port}" OPENSHELL_ISSUER_E2E_MINTER_ENDPOINT="https://${address}:${minter_port}"
# testkit, not a bespoke test framework, owns readiness, SDK/CLI execution and sandbox cleanup.
cargo run --locked --manifest-path "${ROOT}/tests/testkit/Cargo.toml" --bin testkit-ready -- 120
cargo test --locked --manifest-path "${ROOT}/tests/suites/features/Cargo.toml" -p openshell-test-feature-credential-issuer \
  --test remote -- --test-threads 1 --nocapture 2>&1 | tee "${results}/tests.log"
echo 'Cross-cluster issuer public lifecycle, supervisor delivery, outage/watch recovery and mTLS denial passed.'
