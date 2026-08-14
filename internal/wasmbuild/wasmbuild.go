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
	"slices"
	"strings"

	"tailscale.com/feature/featuretags"
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

// keep is the set of tailscale.com feature tags the wasm build needs
// linked; every other feature in the featuretags registry is excluded
// via its ts_omit_ build tag, following cmd/tsconnect/wasmbuild.
// tailcat uses the data plane only, so it needs little: netstack for
// userspace TCP (wasm has no kernel TUN) and nothing else. Omitting
// the rest shrinks the wasm binary by about 6 MB (18%).
var keep = []featuretags.FeatureTag{
	"netstack",
}

// Tags returns the comma-joined -tags value for the wasm build,
// sorted so the same source tree always produces the same wasm bytes.
func Tags() string {
	keepSet := map[featuretags.FeatureTag]bool{}
	for _, ft := range keep {
		for dep := range featuretags.Requires(ft) {
			keepSet[dep] = true
		}
	}
	tags := []string{"osusergo", "netgo", "omitidna", "omitpemdecrypt"}
	for ft := range featuretags.Features {
		if ft == "" || !ft.IsOmittable() {
			continue
		}
		if !keepSet[ft] {
			tags = append(tags, ft.OmitTag())
		}
	}
	slices.Sort(tags)
	return strings.Join(tags, ",")
}

// Build compiles the Go package in pkgDir for js/wasm and writes the
// binary to outPath.
func Build(pkgDir, outPath string) error {
	cmd := exec.Command("go", "build", "-tags", Tags(), "-ldflags=-s -w", "-o", outPath, pkgDir)
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %v: %v\n%s", pkgDir, err, out)
	}
	return nil
}
