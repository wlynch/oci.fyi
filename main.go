package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/fulcio/pkg/certificate"
)

func main() {
	ref, err := name.ParseReference("cgr.dev/chainguard/go:latest")
	if err != nil {
		log.Fatalf("error parsing reference: %v", err)
	}

	sigRef, err := ociremote.SignatureTag(ref)
	if err != nil {
		log.Fatalf("error getting signature tag: %v", err)
	}

	sig, err := getSignature(sigRef)
	if err != nil {
		log.Fatalf("error getting signature: %v", err)
	}

	if err := render(os.Stdout, ref, sig); err != nil {
		log.Fatal(err)
	}
}

var (
	tmpl = template.Must(
		template.New("").
			Funcs(template.FuncMap{
				"unix":           func(t int64) time.Time { return time.Unix(t, 0) },
				"shaURL":         shaURL,
				"buildConfigURL": buildConfigURL,
			}).
			ParseFiles("template.md"),
	)
)

func render(w io.Writer, ref name.Reference, sigs []*SignatureData) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(sigs)
	return tmpl.ExecuteTemplate(w, "template.md", struct {
		Ref  name.Reference
		Sigs []*SignatureData
	}{
		Ref:  ref,
		Sigs: sigs,
	})
}

type SignatureData struct {
	Bundle     *bundle.RekorBundle
	Cert       *x509.Certificate
	Extensions certificate.Extensions
}

func getSignature(ref name.Reference) ([]*SignatureData, error) {
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
			}
		}
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
		path := strings.TrimPrefix(ext.BuildConfigURI, ext.SourceRepositoryOwnerURI)
		path, _, _ = strings.Cut(path, "@")
		path = strings.Trim(path, "/")
		return fmt.Sprintf("%s/blob/%s/%s", ext.SourceRepositoryURI, ext.BuildConfigDigest, path)
	}
	return ext.BuildConfigURI
}
