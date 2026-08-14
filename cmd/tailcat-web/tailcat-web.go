// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tailcat-web command is a development server for the tailcat
// browser app in the web/ directory. It builds the js/wasm binary at
// startup and serves the static files, plus a same-origin
// /derpmap.json proxy so the browser's DERP map fetch (which sends a
// Tailcat-Mode header) doesn't require CORS support upstream.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tailscale/tailcat"
	"github.com/tailscale/tailcat/internal/wasmbuild"
)

var (
	flagListen     = flag.String("listen", "localhost:8080", "HTTP listen address")
	flagDERPMapURL = flag.String("derpmap-url", tailcat.DefaultDERPMapURL, "upstream URL of the JSON DERP map, proxied at /derpmap.json")
	flagWebDir     = flag.String("web-dir", "web", "path to the web/ directory with index.html and app.js")
)

func main() {
	flag.Parse()

	tmpDir, err := os.MkdirTemp("", "tailcat-web")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	wasmPath := filepath.Join(tmpDir, "main.wasm")

	pkgArg := *flagWebDir
	if !filepath.IsAbs(pkgArg) {
		pkgArg = "./" + filepath.ToSlash(pkgArg)
	}
	t0 := time.Now()
	log.Printf("building %s ...", wasmPath)
	if err := wasmbuild.Build(pkgArg, wasmPath); err != nil {
		log.Fatal(err)
	}
	log.Printf("built wasm in %v", time.Since(t0).Round(time.Millisecond))

	wasmExecJS, err := wasmbuild.WasmExecJS()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(*flagWebDir, "index.html"))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(*flagWebDir, "app.js"))
	})
	mux.HandleFunc("/wasm_exec.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, wasmExecJS)
	})
	mux.HandleFunc("/main.wasm", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, wasmPath)
	})
	mux.HandleFunc("/derpmap.json", func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), "GET", *flagDERPMapURL, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Tailcat-Mode", r.Header.Get("Tailcat-Mode"))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.StatusCode)
		io.Copy(w, res.Body)
	})

	log.Printf("serving tailcat web app at http://%s/", *flagListen)
	log.Fatal(http.ListenAndServe(*flagListen, mux))
}
