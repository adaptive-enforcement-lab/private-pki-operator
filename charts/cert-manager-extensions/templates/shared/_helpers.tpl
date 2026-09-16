{{/*
Expand the name of the chart.
*/}}
{{- define "cert-manager-extensions.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cert-manager-extensions.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "cert-manager-extensions.labels" -}}
helm.sh/chart: {{ include "cert-manager-extensions.chart" . }}
app.kubernetes.io/name: {{ include "cert-manager-extensions.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: {{ .Values.labels.component }}
app.kubernetes.io/part-of: {{ .Release.Name }}
argocd.argoproj.io/instance: {{ .Release.Name }}
environment: {{ .Values.labels.environment }}
app: cert-manager-extensions
{{- end }}
