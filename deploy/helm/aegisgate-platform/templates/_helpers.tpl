{{- /*
AegisGate Security Platform — Helm Templates
Copyright 2024 AegisGate Security. All rights reserved.
*/}}

{{- define "aegisgate-platform.labels" -}}
app.kubernetes.io/name: aegisgate-platform
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "aegisgate-platform.selectorLabels" -}}
app.kubernetes.io/name: aegisgate-platform
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}