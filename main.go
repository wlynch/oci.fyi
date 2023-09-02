package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/fulcio/pkg/certificate"
	"golang.org/x/exp/slog"
)

const (
	defaultPage = `<html>
<head>
<link rel="stylesheet" href="https://cdn.simplecss.org/simple.min.css">
</head>
<body>
<h1>oci.fyi</h1>
<form action="/" method="GET" autocomplete="off" spellcheck="false">
<input size="100" type="text" name="image" value="cgr.dev/chainguard/static">
<input type="submit">
</form>
</body>
</html>`
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		image := r.URL.Query().Get("image")
		if image == "" {
			w.Write([]byte(defaultPage))
			return
		}
		// Render markdown, then pass to html/template.
		// This was just easier to prototype than trying to deal with html/css.
		ref, err := name.ParseReference(image)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b := new(bytes.Buffer)
		if err := handleRef(b, ref); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(b.String())

		// Render to HTML
		p := parser.NewWithExtensions(parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock | parser.Tables)
		doc := p.Parse(b.Bytes())
		opts := html.RendererOptions{
			Title: "asdf",
			Flags: html.CommonFlags | html.HrefTargetBlank | html.CompletePage,
			CSS:   "https://cdn.simplecss.org/simple.min.css",
		}
		renderer := html.NewRenderer(opts)

		w.Write(markdown.Render(doc, renderer))
	})
	http.ListenAndServe(":8080", nil)
}

func handleRef(w io.Writer, ref name.Reference) error {
	desc, err := remote.Head(ref)
	if err != nil {
		return fmt.Errorf("error getting remote image: %w", err)
	}

	sig, err := getSignature(ref)
	if err != nil {
		slog.Warn("%v", err)
	}

	att, err := getAttestations(ref)
	if err != nil {
		slog.Warn("%v", err)
	}

	return tmpl.ExecuteTemplate(w, "template.md", struct {
		Ref         name.Reference
		ResolvedRef name.Reference
		Sigs        []*SignatureData
		Att         []*SignatureData
	}{
		Ref:         ref,
		ResolvedRef: ref.Context().Digest(desc.Digest.String()),
		Sigs:        sig,
		Att:         att,
	})
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
			}).
			ParseFS(fs, "template.md"),
	)
)

type SignatureData struct {
	Bundle        *bundle.RekorBundle
	Cert          *x509.Certificate
	Extensions    certificate.Extensions
	Predicate     name.Reference
	PredicateType string
}

func getSignature(ref name.Reference) ([]*SignatureData, error) {
	sigRef, err := ociremote.SignatureTag(ref)
	if err != nil {
		return nil, fmt.Errorf("error getting signature tag: %v", err)
	}

	return getData(sigRef)
}

func getData(ref name.Reference) ([]*SignatureData, error) {
	img, err := remote.Image(ref)
	if err != nil {
		return nil, fmt.Errorf("error getting remote image: %w", err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("error getting manifest: %w", err)
	}

	var out []*SignatureData
	for _, l := range manifest.Layers {
		s := new(SignatureData)
		for k, v := range l.Annotations {
			switch k {
			case "dev.sigstore.cosign/bundle":
				bundle := new(bundle.RekorBundle)
				if err := json.Unmarshal([]byte(v), bundle); err != nil {
					return nil, fmt.Errorf("error unmarshalling bundle: %w", err)
				}
				s.Bundle = bundle

			case "dev.sigstore.cosign/certificate":
				data, _ := pem.Decode([]byte(v))
				cert, err := x509.ParseCertificate(data.Bytes)
				if err != nil {
					return nil, fmt.Errorf("error parsing cert: %w", err)
				}
				s.Cert = cert
				ext, err := parseExtensions(cert.Extensions)
				if err != nil {
					return nil, fmt.Errorf("error parsing extensions: %w", err)
				}

				s.Extensions = ext
			case "predicateType":
				s.PredicateType = v
			}
		}
		s.Predicate = ref.Context().Digest(l.Digest.String())
		out = append(out, s)
	}
	return out, nil
}

func parseExtensions(ext []pkix.Extension) (certificate.Extensions, error) {
	out := certificate.Extensions{}

	for _, e := range ext {
		switch {
		// BEGIN: Deprecated
		case e.Id.Equal(certificate.OIDIssuer):
			out.Issuer = string(e.Value)
		case e.Id.Equal(certificate.OIDGitHubWorkflowTrigger):
			out.GithubWorkflowTrigger = string(e.Value)
		case e.Id.Equal(certificate.OIDGitHubWorkflowSHA):
			out.GithubWorkflowSHA = string(e.Value)
		case e.Id.Equal(certificate.OIDGitHubWorkflowName):
			out.GithubWorkflowName = string(e.Value)
		case e.Id.Equal(certificate.OIDGitHubWorkflowRepository):
			out.GithubWorkflowRepository = string(e.Value)
		case e.Id.Equal(certificate.OIDGitHubWorkflowRef):
			out.GithubWorkflowRef = string(e.Value)
		// END: Deprecated
		case e.Id.Equal(certificate.OIDIssuerV2):
			if err := certificate.ParseDERString(e.Value, &out.Issuer); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDBuildSignerURI):
			if err := certificate.ParseDERString(e.Value, &out.BuildSignerURI); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDBuildSignerDigest):
			if err := certificate.ParseDERString(e.Value, &out.BuildSignerDigest); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDRunnerEnvironment):
			if err := certificate.ParseDERString(e.Value, &out.RunnerEnvironment); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDSourceRepositoryURI):
			if err := certificate.ParseDERString(e.Value, &out.SourceRepositoryURI); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDSourceRepositoryDigest):
			if err := certificate.ParseDERString(e.Value, &out.SourceRepositoryDigest); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDSourceRepositoryRef):
			if err := certificate.ParseDERString(e.Value, &out.SourceRepositoryRef); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDSourceRepositoryIdentifier):
			if err := certificate.ParseDERString(e.Value, &out.SourceRepositoryIdentifier); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDSourceRepositoryOwnerURI):
			if err := certificate.ParseDERString(e.Value, &out.SourceRepositoryOwnerURI); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDSourceRepositoryOwnerIdentifier):
			if err := certificate.ParseDERString(e.Value, &out.SourceRepositoryOwnerIdentifier); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDBuildConfigURI):
			if err := certificate.ParseDERString(e.Value, &out.BuildConfigURI); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDBuildConfigDigest):
			if err := certificate.ParseDERString(e.Value, &out.BuildConfigDigest); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDBuildTrigger):
			if err := certificate.ParseDERString(e.Value, &out.BuildTrigger); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDRunInvocationURI):
			if err := certificate.ParseDERString(e.Value, &out.RunInvocationURI); err != nil {
				return certificate.Extensions{}, err
			}
		case e.Id.Equal(certificate.OIDSourceRepositoryVisibilityAtSigning):
			if err := certificate.ParseDERString(e.Value, &out.SourceRepositoryVisibilityAtSigning); err != nil {
				return certificate.Extensions{}, err
			}
		}
	}

	// We only ever return nil, but leaving error in place so that we can add
	// more complex parsing of fields in a backwards compatible way if needed.
	return out, nil
}

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

func getAttestations(ref name.Reference) ([]*SignatureData, error) {
	attRef, err := ociremote.AttestationTag(ref)
	if err != nil {
		return nil, fmt.Errorf("error getting signature tag: %v", err)
	}

	return getData(attRef)
}

func issuerIcon(issuer string) string {
	switch issuer {
	case "https://token.actions.githubusercontent.com":
		return "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"
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
