// SPDX-License-Identifier: Apache-2.0

// Command vectors maintains the conformance files of the Relay Specification:
//
//	vectors manifest [-check]   write or check conformance/manifest.json
//	vectors relay-jws <keys>    print conformance/jws-v0.json, the requests of the Relay
//	                            Specification (RELAY-v0 sections 5.1, 5.5), signed with test keys
//	vectors relay-csr <keys>    print conformance/csr-v0.json, certificate signing requests
//	                            for tunnel certificates (RELAY-v0 section 5.4)
//	vectors relay-certificate <keys>
//	                            print conformance/certificate-v0.json, issued tunnel
//	                            certificates (RELAY-v0 section 5.4)
//	vectors relay-proxy         print conformance/proxy-v0.json, PROXY headers as a gateway
//	                            reads them (RELAY-v0 section 4.6)
//
// Run it from the repository root: go run ./tools/vectors <command>.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/home-mandate/spec/manifest"

	relay "github.com/home-mandate/relay-spec"
)

func main() {
	if err := run(os.Args[1:], ".", os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vectors:", err)
		os.Exit(1)
	}
}

// run executes one command with paths relative to dir.
func run(args []string, dir string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: vectors manifest [-check] | relay-jws <keys> | relay-csr <keys> | relay-certificate <keys> | relay-proxy")
	}
	switch args[0] {
	case "manifest":
		return runManifest(args[1:], dir, stdout)
	case "relay-jws":
		return runRelayJWS(args[1:], dir, stdout)
	case "relay-csr":
		return runRelayCSR(args[1:], dir, stdout)
	case "relay-certificate":
		return runRelayCertificate(args[1:], dir, stdout)
	case "relay-proxy":
		return runRelayProxy(args[1:], stdout)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func runManifest(args []string, dir string, stdout io.Writer) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check", false, "compare instead of writing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return errors.New("usage: vectors manifest [-check]")
	}
	layout := relay.ManifestLayout
	built, err := layout.Build(os.DirFS(dir))
	if err != nil {
		return err
	}
	target := filepath.Join(dir, filepath.FromSlash(layout.Path))
	if !*check {
		data, err := manifest.Encode(built)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		_, err = fmt.Fprintf(stdout, "%s: %d files\n", layout.Path, len(built.Files))
		return err
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	stored, err := manifest.Decode(data)
	if err != nil {
		return err
	}
	if diff := manifest.Diff(built, stored); len(diff) > 0 {
		return fmt.Errorf("%s is out of date: %v", layout.Path, diff)
	}
	return nil
}
