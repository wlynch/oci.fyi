# [oci.fyi](/)

<form action="/" method="GET" autocomplete="off" spellcheck="false">
<input size="100" type="text" name="image" value="{{.Ref}}">
<input type="submit">

[{{ .ResolvedRef }}](https://oci.dag.dev/?image={{ .ResolvedRef }})

{{ range .Data }}

## [{{ .Name }}](#{{ lower .Name }})

{{ if .Digest -}}
[(manifest)](https://oci.dag.dev/?image={{ .Digest }})
{{- else -}}
😢 This image has no {{ .Name }}
{{- end }}

{{ range .Data }}
--|--
Payload | [{{ .LayerType }}](https://oci.dag.dev/?blob={{ .Layer }})
{{ if .PredicateType -}}
Predicate | [{{ .PredicateType }}](https://oci.dag.dev/?blob={{ .Layer }}&jq=.payload&jq=base64+-d&jq=jq)
{{ end -}}
{{- if .Bundle -}}
Date | {{ unix .Bundle.Payload.IntegratedTime }}
LogIndex | [{{ .Bundle.Payload.LogIndex }}](https://search.sigstore.dev/?logIndex={{ .Bundle.Payload.LogIndex }})
{{ end -}}
Identity | {{ with subjectAltName .Cert }}`{{ . }}`{{ end }}
{{ with .Extensions -}}
Issuer | {{ with .Issuer }}<img src="{{ issuerIcon . }}" width="20"/> `{{ . }}`{{ end }}
{{- if .SourceRepositoryURI }}
Repo | [{{ .SourceRepositoryURI }}]({{ .SourceRepositoryURI }})
SHA | [{{ slice .SourceRepositoryDigest 32 }}]({{ shaURL .SourceRepositoryURI .SourceRepositoryDigest }})
Ref | {{ .SourceRepositoryRef }}
Build | {{ .RunInvocationURI }}
Build Config | [{{ .BuildConfigURI }} ({{ slice .BuildConfigDigest 32 }})]({{ buildConfigURL . }})
{{- end }}
{{- end }}
{{ end }}
{{ end -}}
