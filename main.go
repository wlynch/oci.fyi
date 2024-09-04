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
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/exp/slog"
)

const (
	defaultPage = `<html>
<head>
<link rel="stylesheet" href="https://cdn.simplecss.org/simple.min.css">
</head>
<body>
<h1 id="oci-fyi"><a href="/">oci.fyi</a></h1>
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
		if os.Getenv("DEBUG") != "" {
			fmt.Println(b)
		}

		// Render to HTML
		p := parser.NewWithExtensions(parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock | parser.Tables)
		doc := p.Parse(b.Bytes())
		opts := html.RendererOptions{
			Title: r.Host,
			Flags: html.CommonFlags | html.HrefTargetBlank | html.CompletePage,
			CSS:   "https://cdn.simplecss.org/simple.min.css",
		}
		renderer := html.NewRenderer(opts)

		w.Write(markdown.Render(doc, renderer))
	})
	http.ListenAndServe(":8080", nil)
}

func handleRef(w io.Writer, ref name.Reference) error {
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	desc, err := remote.Head(ref, opts...)
	if err != nil {
		return fmt.Errorf("error getting remote image: %w", err)
	}

	sigDigest, sigData, err := getSignature(ref, opts...)
	if err != nil {
		slog.Warn("%v", err)
	}

	attDigest, attData, err := getAttestations(ref, opts...)
	if err != nil {
		slog.Warn("%v", err)
	}

	return tmpl.ExecuteTemplate(w, "template.md", &output{
		Ref:         ref,
		ResolvedRef: ref.Context().Digest(desc.Digest.String()),
		Data: []*manifest{
			{
				Name:   "Signatures",
				Digest: sigDigest.String(),
				Data:   sigData,
			},
			{
				Name:   "Attestations",
				Digest: attDigest.String(),
				Data:   attData,
			},
		},
	})
}
