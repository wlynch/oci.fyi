# {{ .Ref.Name }}

## Signatures

{{ range .Sigs -}}

- Date: {{ unix .Bundle.Payload.IntegratedTime }}
  LogIndex: [{{ .Bundle.Payload.LogIndex }}](https://search.sigstore.dev/?logIndex={{ .Bundle.Payload.LogIndex }})
  {{ with .Extensions -}}
  {{ if .SourceRepositoryURI -}}
  Repo: [{{ .SourceRepositoryURI }}]({{ .SourceRepositoryURI }})
  SHA: [{{ slice .SourceRepositoryDigest 32 }}]({{ shaURL .SourceRepositoryURI .SourceRepositoryDigest }})
  Ref: {{ .SourceRepositoryRef }}
  Build: {{ .RunInvocationURI }}
  Build Config: [{{ .BuildConfigURI }} ({{ slice .BuildConfigDigest 32 }})]({{ buildConfigURL . }})
  {{ end -}}
  {{ end }}
{{ end -}}
