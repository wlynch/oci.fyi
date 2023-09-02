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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/fulcio/pkg/certificate"
)

type SignatureData struct {
	Bundle        *bundle.RekorBundle
	Cert          *x509.Certificate
	Extensions    certificate.Extensions
	Layer         name.Reference
	LayerType     string
	PredicateType string
}

func getSignature(ref name.Reference) (name.Digest, []*SignatureData, error) {
	sigRef, err := ociremote.SignatureTag(ref)
	if err != nil {
		return name.Digest{}, nil, fmt.Errorf("error getting signature tag: %v", err)
	}

	return getData(sigRef)
}

func getData(ref name.Reference) (name.Digest, []*SignatureData, error) {
	img, err := remote.Image(ref)
	if err != nil {
		return name.Digest{}, nil, fmt.Errorf("error getting remote image: %w", err)
	}
	d, err := img.Digest()
	if err != nil {
		return name.Digest{}, nil, fmt.Errorf("error getting digest: %v", err)
	}
	digest := ref.Context().Digest(d.String())
	manifest, err := img.Manifest()
	if err != nil {
		return digest, nil, fmt.Errorf("error getting manifest: %w", err)
	}

	var out []*SignatureData
	for _, l := range manifest.Layers {
		s := new(SignatureData)
		for k, v := range l.Annotations {
			switch k {
			case "dev.sigstore.cosign/bundle":
				bundle := new(bundle.RekorBundle)
				if err := json.Unmarshal([]byte(v), bundle); err != nil {
					return digest, nil, fmt.Errorf("error unmarshalling bundle: %w", err)
				}
				s.Bundle = bundle

			case "dev.sigstore.cosign/certificate":
				data, _ := pem.Decode([]byte(v))
				cert, err := x509.ParseCertificate(data.Bytes)
				if err != nil {
					return digest, nil, fmt.Errorf("error parsing cert: %w", err)
				}
				s.Cert = cert
				ext, err := parseExtensions(cert.Extensions)
				if err != nil {
					return digest, nil, fmt.Errorf("error parsing extensions: %w", err)
				}

				s.Extensions = ext
			case "predicateType":
				s.LayerType = v
			}
		}
		s.LayerType = string(l.MediaType)
		layerDigest := ref.Context().Digest(l.Digest.String())
		s.Layer = layerDigest

		if l.MediaType == "application/vnd.dsse.envelope.v1+json" {
			intoto, err := readDSSEHeader(layerDigest)
			if err != nil {
				return digest, nil, fmt.Errorf("error reading intoto header: %w", err)
			}
			if intoto != nil {
				s.PredicateType = intoto.PredicateType
			}
		}

		out = append(out, s)
	}
	return digest, out, nil
}

func readDSSEHeader(digest name.Digest) (*in_toto.StatementHeader, error) {
	blob, err := remote.Layer(digest)
	if err != nil {
		return nil, fmt.Errorf("error getting layer: %w", err)
	}
	r, err := blob.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("error getting layer content: %w", err)
	}
	defer r.Close()

	env := new(dsse.Envelope)
	if err := json.NewDecoder(r).Decode(env); err != nil {
		return nil, fmt.Errorf("error decoding dsse envelope: %w", err)
	}
	if env.PayloadType != "application/vnd.in-toto+json" {
		return nil, nil
	}

	out := new(in_toto.StatementHeader)
	if err := json.NewDecoder(base64.NewDecoder(base64.StdEncoding, bytes.NewBufferString(env.Payload))).Decode(out); err != nil {
		return nil, fmt.Errorf("error decoding intoto statement: %w", err)
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
