{{/*
MPC Wallet Helm Chart — Template Helpers
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "mpc-wallet.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "mpc-wallet.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mpc-wallet.labels" -}}
helm.sh/chart: {{ include "mpc-wallet.name" . }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Gateway selector labels
*/}}
{{- define "mpc-wallet.gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mpc-wallet.name" . }}-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Node selector labels
*/}}
{{- define "mpc-wallet.node.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mpc-wallet.name" . }}-node
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "mpc-wallet.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "mpc-wallet.fullname" . }}
{{- end }}
{{- end }}
