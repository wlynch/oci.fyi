// Copyright 2023 The oci.fyi Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/x509"
	"embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/fulcio/pkg/certificate"
)

type output struct {
	Ref         name.Reference
	ResolvedRef name.Reference
	Data        []*manifest
}

type manifest struct {
	Name   string
	Digest string
	Data   []*SignatureData
}

var (
	//go:embed "template.md"
	fs   embed.FS
	tmpl = template.Must(
		template.New("").
			Funcs(template.FuncMap{
				"unix":           func(t int64) time.Time { return time.Unix(t, 0) },
				"shaURL":         shaURL,
				"buildConfigURL": buildConfigURL,
				"issuerIcon":     issuerIcon,
				"subjectAltName": subjectAltName,
				"lower":          strings.ToLower,
			}).
			ParseFS(fs, "template.md"),
	)
)

func shaURL(repo, sha string) string {
	if strings.HasPrefix(repo, "https://github.com") {
		return fmt.Sprintf("%s/commit/%s", repo, sha)
	}
	return repo
}

func buildConfigURL(ext certificate.Extensions) string {
	if strings.HasPrefix(ext.BuildConfigURI, "https://github.com") {
		path := strings.TrimPrefix(ext.BuildConfigURI, ext.SourceRepositoryURI)
		path, _, _ = strings.Cut(path, "@")
		path = strings.Trim(path, "/")
		return fmt.Sprintf("%s/blob/%s/%s", ext.SourceRepositoryURI, ext.BuildConfigDigest, path)
	}
	return ext.BuildConfigURI
}

func getAttestations(ref name.Reference) (name.Digest, []*SignatureData, error) {
	attRef, err := ociremote.AttestationTag(ref)
	if err != nil {
		return name.Digest{}, nil, fmt.Errorf("error getting signature tag: %v", err)
	}

	return getData(attRef)
}

func issuerIcon(issuer string) string {
	switch issuer {
	case "https://token.actions.githubusercontent.com":
		return "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"
	case "https://gitlab.com":
		return "https://about.gitlab.com/images/press/press-kit-icon.svg"
	case "https://accounts.google.com":
		return "https://lh3.googleusercontent.com/COxitqgJr1sJnIDe8-jiKhxDx1FrYbtRHKJ9z_hELisAlapwE9LUPh6fcXIfb5vwpbMl4xl9H9TRFPc5NOO8Sb3VSgIBrfRYvW6cUA"
	}
	return ""
}

func subjectAltName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	url := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		url = append(url, u.String())
	}
	return strings.Join(append(cert.EmailAddresses, url...), " ")
}
