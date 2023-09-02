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
{{ with .Extensions -}}
Issuer | <img src="{{ issuerIcon .Issuer }}" width="20"/> `{{ .Issuer }}`
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
{{ with .Extensions -}}
Issuer | <img src="{{ issuerIcon .Issuer }}" width="20"/> `{{ .Issuer }}`
{{ if .SourceRepositoryURI -}}
Repo | [{{ .SourceRepositoryURI }}]({{ .SourceRepositoryURI }})
SHA | [{{ slice .SourceRepositoryDigest 32 }}]({{ shaURL .SourceRepositoryURI .SourceRepositoryDigest }})
Ref | {{ .SourceRepositoryRef }}
Build | {{ .RunInvocationURI }}
Build Config | [{{ .BuildConfigURI }} ({{ slice .BuildConfigDigest 32 }})]({{ buildConfigURL . }})
{{ end -}}
{{ end }}
{{ end -}}
