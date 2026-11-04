{{/* SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. */}}
{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "issuer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "issuer.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "issuer.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "issuer.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- define "issuer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "issuer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "issuer.labels" -}}
{{ include "issuer.selectorLabels" . }}
app.kubernetes.io/component: credential-issuer
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}
{{- define "issuer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "issuer.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
{{- define "issuer.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}
{{- define "issuer.validate" -}}
{{- $_ := required "config.existingSecret is required; never put issuer TOML or SQL credentials in values" .Values.config.existingSecret -}}
{{- $_ := required "tls.existingSecret is required; issuer mTLS cannot be disabled" .Values.tls.existingSecret -}}
{{- $_ := required "encryption.existingSecret is required; provision a shared 32-byte key" .Values.encryption.existingSecret -}}
{{- if and (gt (int .Values.replicaCount) 1) (ne .Values.database.kind "postgresql") -}}
{{- fail "multiple issuer replicas require database.kind=postgresql and a matching PostgreSQL URL in the config Secret" -}}
{{- end -}}
{{- if and (eq .Values.database.kind "sqlite") (empty .Values.database.existingClaim) -}}
{{- fail "SQLite requires database.existingClaim for durable issuer state" -}}
{{- end -}}
{{- $names := dict -}}
{{- range .Values.registrationSecrets -}}
{{- if hasKey $names .name -}}{{- fail "registrationSecrets names must be unique" -}}{{- end -}}
{{- $_ := set $names .name true -}}
{{- end -}}
{{- end -}}
