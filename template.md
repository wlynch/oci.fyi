# [oci.fyi](/)

<form action="/" method="GET" autocomplete="off" spellcheck="false">
<input size="100" type="text" name="image" value="{{.Ref}}">
<input type="submit">

[{{ .ResolvedRef }}](https://oci.dag.dev/?image={{ .ResolvedRef }})

## [Signatures](#signatures)

{{ range .Sigs -}}

--|--
{{ if .Bundle -}}
Date | {{ unix .Bundle.Payload.IntegratedTime }}
LogIndex | [{{ .Bundle.Payload.LogIndex }}](https://search.sigstore.dev/?logIndex={{ .Bundle.Payload.LogIndex }})
{{ end -}}
Identity | {{ with subjectAltName .Cert }}`{{ . }}`{{ end }}
{{ with .Extensions -}}
Issuer | {{ with .Issuer }}<img src="{{ issuerIcon . }}" width="20"/> `{{ . }}`{{ end }}
{{ if .SourceRepositoryURI -}}
Repo | [{{ .SourceRepositoryURI }}]({{ .SourceRepositoryURI }})
SHA | [{{ slice .SourceRepositoryDigest 32 }}]({{ shaURL .SourceRepositoryURI .SourceRepositoryDigest }})
Ref | {{ .SourceRepositoryRef }}
Build | {{ .RunInvocationURI }}
Build Config | [{{ .BuildConfigURI }} ({{ slice .BuildConfigDigest 32 }})]({{ buildConfigURL . }})
{{ end -}}
{{ end }}
{{ end -}}

## [Attestations](#attestations)

{{ range .Att -}}

--|--
{{ if .Bundle -}}
Date | {{ unix .Bundle.Payload.IntegratedTime }}
LogIndex | [{{ .Bundle.Payload.LogIndex }}](https://search.sigstore.dev/?logIndex={{ .Bundle.Payload.LogIndex }})
{{ end -}}
PredicateType | {{ .PredicateType }}
Predicate | [{{ .Predicate }}](https://oci.dag.dev/?blob={{ .Predicate }})
Identity | {{ with subjectAltName .Cert }}`{{ . }}`{{end}}
{{ with .Extensions -}}
Issuer | {{ with .Issuer }}<img src="{{ issuerIcon . }}" width="20"/> `{{ . }}`{{ end }}
{{ if .SourceRepositoryURI -}}
Repo | [{{ .SourceRepositoryURI }}]({{ .SourceRepositoryURI }})
SHA | [{{ slice .SourceRepositoryDigest 32 }}]({{ shaURL .SourceRepositoryURI .SourceRepositoryDigest }})
Ref | {{ .SourceRepositoryRef }}
Build | {{ .RunInvocationURI }}
Build Config | [{{ .BuildConfigURI }} ({{ slice .BuildConfigDigest 32 }})]({{ buildConfigURL . }})
{{ end -}}
{{ end }}
{{ end -}}
