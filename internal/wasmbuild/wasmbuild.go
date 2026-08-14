// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wasmbuild builds the tailcat web WebAssembly binary and
// locates the Go toolchain's wasm_exec.js support file. It is shared
// by cmd/tailcat-web and the browser integration tests.
package wasmbuild

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GoRoot returns the GOROOT of the go command in $PATH.
func GoRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOROOT: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// WasmExecJS returns the path to the Go toolchain's wasm_exec.js,
// the JavaScript support file needed to run Go wasm binaries.
func WasmExecJS() (string, error) {
	goroot, err := GoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(goroot, "lib", "wasm", "wasm_exec.js"), nil
}

// Build compiles the Go package in pkgDir for js/wasm and writes the
// binary to outPath.
func Build(pkgDir, outPath string) error {
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outPath, pkgDir)
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %v: %v\n%s", pkgDir, err, out)
	}
	return nil
}
