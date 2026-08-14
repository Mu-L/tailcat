// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tailcat-web command is a development server for the tailcat
// browser app in the web/ directory. It builds the js/wasm binary at
// startup and serves the static files, plus a same-origin
// /derpmap.json proxy so the browser's DERP map fetch (which sends a
// Tailcat-Mode header) doesn't require CORS support upstream.
package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
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

	t0 = time.Now()
	wasmSize, err := compressWasm(wasmPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("compressed wasm in %v", time.Since(t0).Round(time.Millisecond))

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
		// The wasm binary is tens of MB; serve it precompressed.
		// Content-Type is set before ServeFile so it isn't sniffed
		// from the compressed file's extension.
		w.Header().Set("Content-Type", "application/wasm")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("X-Uncompressed-Size", fmt.Sprint(wasmSize))
		ae := r.Header.Get("Accept-Encoding")
		switch {
		case strings.Contains(ae, "zstd"):
			w.Header().Set("Content-Encoding", "zstd")
			http.ServeFile(w, r, wasmPath+".zst")
		case strings.Contains(ae, "gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			http.ServeFile(w, r, wasmPath+".gz")
		default:
			http.ServeFile(w, r, wasmPath)
		}
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

// compressWasm writes path.zst and path.gz next to path and returns
// the uncompressed size.
func compressWasm(path string) (size int64, err error) {
	src, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return 0, err
	}

	zf, err := os.Create(path + ".zst")
	if err != nil {
		return 0, err
	}
	defer zf.Close()
	zw, err := zstd.NewWriter(zf)
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(zw, src); err != nil {
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	gf, err := os.Create(path + ".gz")
	if err != nil {
		return 0, err
	}
	defer gf.Close()
	gw := gzip.NewWriter(gf)
	if _, err := io.Copy(gw, src); err != nil {
		return 0, err
	}
	if err := gw.Close(); err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
