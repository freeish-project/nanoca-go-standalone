{{/*
Expand the name of the chart.
*/}}
{{- define "nanoca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. Truncated at 63 chars (DNS-1123 label limit).
*/}}
{{- define "nanoca.fullname" -}}
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
Chart name + version label.
*/}}
{{- define "nanoca.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "nanoca.labels" -}}
helm.sh/chart: {{ include "nanoca.chart" . }}
{{ include "nanoca.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (must remain stable across upgrades).
*/}}
{{- define "nanoca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nanoca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "nanoca.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nanoca.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret name to use. Either chart-managed (when secrets.create=true) or
the deployer-supplied existingSecret. Fails the install if neither is set.
*/}}
{{- define "nanoca.secretName" -}}
{{- if .Values.secrets.create }}
{{- include "nanoca.fullname" . }}
{{- else if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- fail "Either secrets.create=true or secrets.existingSecret must be set. See values.yaml comments for the security tradeoffs." }}
{{- end }}
{{- end }}

{{/*
ConfigMap name.
*/}}
{{- define "nanoca.configMapName" -}}
{{- printf "%s-config" (include "nanoca.fullname" .) }}
{{- end }}

{{/*
Resolved image reference. Prefers digest over tag when both are set.
*/}}
{{- define "nanoca.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Tunnel-token Secret reference (sidecar). Honours existingTokenSecret override.
*/}}
{{- define "nanoca.tunnelSecretName" -}}
{{- if .Values.cloudflared.existingTokenSecret -}}
{{- .Values.cloudflared.existingTokenSecret -}}
{{- else -}}
{{- include "nanoca.secretName" . -}}
{{- end -}}
{{- end }}
