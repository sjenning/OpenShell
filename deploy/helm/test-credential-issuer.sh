#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
chart="${root}/deploy/helm/openshell-credential-issuer"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
if [[ -z "${ISSUER_BIN:-}" ]]; then
  cargo build --quiet --package openshell-credential-issuer
  ISSUER_BIN="${root}/target/debug/openshell-credential-issuer"
fi
render() {
  helm template issuer "${chart}" --namespace security -f "${chart}/ci/values-test.yaml" "$@"
}
reject() {
  if render "$@" >"${work}/rejected.yaml" 2>"${work}/error"; then
    echo "FAIL: chart accepted invalid values: $*" >&2
    exit 1
  fi
}
expect() {
  # Use per-document evaluation; eval-all can cross-join documents inside
  # compound boolean predicates, masking a failed boundary assertion.
  yq e "$1" "${work}/render.yaml" | grep -x true >/dev/null
}
render >"${work}/render.yaml"
expect 'select(.kind == "Service") | .spec.type == "ClusterIP" and (.spec.ports | length) == 1 and .spec.ports[0].port == 8443'
expect 'select(.kind == "Deployment") | .spec.template.spec.containers[0].image == "ghcr.io/nvidia/openshell/credential-issuer:0.0.0"'
expect 'select(.kind == "Deployment") | .spec.template.spec.containers[0].args[0] == "--config" and .spec.template.spec.containers[0].args[1] == "/etc/openshell-issuer/config/issuer.toml" and (.spec.template.spec.containers[0].args | length) == 2'
expect 'select(.kind == "Deployment") | .spec.template.spec.initContainers[1].args[2] == "--check-config"'
expect 'select(.kind == "Deployment") | .spec.template.spec.securityContext.runAsNonRoot and .spec.template.spec.securityContext.fsGroup == 1000'
expect 'select(.kind == "Deployment") | .spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem and .spec.template.spec.automountServiceAccountToken == false'
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == "config") | .secret.secretName == "issuer-config"'
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == "config") | .secret.defaultMode == 0440'
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == "tls") | (.secret.items | length) == 3'
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == "encryption") | .emptyDir.medium == "Memory"'
expect 'select(.kind == "Deployment") | .spec.template.spec.initContainers[0].name == "prepare-key"'
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == "encryption-source") | .secret.secretName == "issuer-kek"'
if yq ea -r '.kind' "${work}/render.yaml" | grep -Eq '^(Secret|ConfigMap|Ingress|GRPCRoute|Gateway|Role|ClusterRole|StatefulSet)$'; then
  echo "FAIL: chart rendered credentials, gateway resources, or implicit backend RBAC" >&2; exit 1
fi
if grep -Eq 'postgres(ql)?://|database_url|BEGIN .*PRIVATE KEY|containerPort: 8080|subPath:' "${work}/render.yaml"; then
  echo "FAIL: credentials or gateway listener escaped into chart output" >&2; exit 1
fi
reject --set config.existingSecret=
reject --set tls.existingSecret=
reject --set encryption.existingSecret=
reject --set replicaCount=0
reject --set replicaCount=2 --set database.kind=sqlite --set database.existingClaim=issuer-data
reject --set database.kind=sqlite
reject --set tls.disable=true
reject --set config.database_url=postgresql://do-not-inline
reject --set service.type=LoadBalancer
reject --set-json 'registrationSecrets=[{"name":"../escape","secretName":"identity"}]'
reject --set-json 'registrationSecrets=[{"name":"same","secretName":"a"},{"name":"same","secretName":"b"}]'
# The registration- prefix consumes 13 of Kubernetes' 63 volume-name characters.
# Reject both the first invalid length and the previously accepted DNS maximum.
registration_name="$(printf 'r%049d' 0)"
reject --set-string "registrationSecrets[0].name=${registration_name}x" --set 'registrationSecrets[0].secretName=identity'
reject --set-string "registrationSecrets[0].name=${registration_name}1234567890123" --set 'registrationSecrets[0].secretName=identity'
render --set-string "registrationSecrets[0].name=${registration_name}" --set 'registrationSecrets[0].secretName=identity' >"${work}/render.yaml"
export REGISTRATION_NAME="${registration_name}"
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == ("registration-" + strenv(REGISTRATION_NAME))) | .name | length == 63'
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == ("registration-" + strenv(REGISTRATION_NAME))) | .secret.secretName == "identity"'
expect 'select(.kind == "Deployment") | .spec.template.spec.containers[0].volumeMounts[] | select(.name == ("registration-" + strenv(REGISTRATION_NAME))) | .mountPath == ("/etc/openshell-issuer/registrations/" + strenv(REGISTRATION_NAME))'
expect 'select(.kind == "Deployment") | .spec.template.spec.containers[0].volumeMounts[] | select(.name == ("registration-" + strenv(REGISTRATION_NAME))) | .readOnly'
render --set replicaCount=3 >"${work}/render.yaml"
expect 'select(.kind == "Deployment") | .spec.replicas == 3 and .spec.strategy.type == "RollingUpdate"'
render --set database.kind=sqlite --set database.existingClaim=issuer-data >"${work}/render.yaml"
expect 'select(.kind == "Deployment") | .spec.strategy.type == "Recreate"'
expect 'select(.kind == "Deployment") | .spec.template.spec.volumes[] | select(.name == "data") | .persistentVolumeClaim.claimName == "issuer-data"'
render --set-json 'registrationSecrets=[{"name":"minter","secretName":"minter-tls"},{"name":"vault","secretName":"vault-token"}]' >"${work}/render.yaml"
expect 'select(.kind == "Deployment") | .spec.template.spec.containers[0].volumeMounts[] | select(.name == "registration-minter") | .mountPath == "/etc/openshell-issuer/registrations/minter"'
expect 'select(.kind == "Deployment") | .spec.template.spec.containers[0].volumeMounts[] | select(.name == "registration-minter") | .readOnly'
render --set-json 'networkPolicy.ingressFrom=[]' >"${work}/render.yaml"
expect 'select(.kind == "NetworkPolicy") | (.spec.ingress | length) == 0'
# Check actual TOML with the service's strict parser; never contact a backend.
cp "${chart}/examples/issuer.toml" "${work}/issuer.toml"
"${ISSUER_BIN}" --config "${work}/issuer.toml" --check-config
sed -e 's/replicas = 1/replicas = 3/' "${chart}/examples/issuer.toml" >"${work}/postgres.toml"
"${ISSUER_BIN}" --config "${work}/postgres.toml" --check-config
sed -e 's|postgresql://issuer-db.security.svc/issuer|sqlite:///var/lib/openshell-issuer/issuer.db?mode=rwc|' "${work}/postgres.toml" >"${work}/invalid.toml"
if "${ISSUER_BIN}" --config "${work}/invalid.toml" --check-config >"${work}/error" 2>&1; then
  echo "FAIL: service accepted multiple SQLite replicas" >&2; exit 1
fi
sed -e 's/\["default"\]/["*"]/' "${chart}/examples/issuer.toml" >"${work}/invalid.toml"
if "${ISSUER_BIN}" --config "${work}/invalid.toml" --check-config >"${work}/error" 2>&1; then
  echo "FAIL: service accepted wildcard workspace authorization" >&2; exit 1
fi
cat >>"${work}/issuer.toml" <<'TOML'
[openshell.credential_issuer.minters.company-sts]
endpoint = "https://minter.security.svc:8443"
tls_ca_cert_path = "/etc/openshell-issuer/registrations/minter/ca.pem"
tls_client_cert_path = "/etc/openshell-issuer/registrations/minter/tls.crt"
tls_client_key_path = "/etc/openshell-issuer/registrations/minter/tls.key"
[openshell.credential_drivers.vault]
address = "https://vault.security.svc:8200"
auth_method = "token_file"
token_path = "/etc/openshell-issuer/registrations/vault/token"
TOML
"${ISSUER_BIN}" --config "${work}/issuer.toml" --check-config
bash "${root}/deploy/helm/test-credential-issuer-key-init.sh"
helm package "${chart}" --destination "${work}" >/dev/null
echo "issuer chart render, Secret boundaries, replica guards, package, and strict configuration checks passed"
