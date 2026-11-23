// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/home-mandate/relay-spec/internal/liveconf"
)

// TestMain lets the test binary serve as the DNS hook, as the command serves as its own.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == hookCommand {
		os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// TestTheReferenceConformsToEveryClass: the reference passes every check of the five classes,
// -ct-verify included, which the command runs right after the run.
func TestTheReferenceConformsToEveryClass(t *testing.T) {
	report := filepath.Join(t.TempDir(), "report.json")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-report", report}, &out, &errOut); code != liveconf.ExitConforms {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var rep liveconf.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Conforms || len(rep.Failures) != 0 || len(rep.Incomplete) != 0 || rep.Spec != liveconf.SpecName || rep.Version != version || rep.CTVerified == "" {
		t.Errorf("report: conforms %v, failures %v, incomplete %v, spec %q, version %q", rep.Conforms, rep.Failures, rep.Incomplete, rep.Spec, rep.Version)
	}
	for _, class := range liveconf.AllClasses {
		if c := rep.Classes[class]; c == nil || c.NotRun || !c.Conforms {
			t.Errorf("class %s: %+v", class, c)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"-report"}, {"-report", "r.json", "extra"}, {"-operator", "op.example.net"}} {
		if code := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); code != liveconf.ExitUsage {
			t.Errorf("run(%q) = %d, want %d", args, code, liveconf.ExitUsage)
		}
	}
}

func TestTheHookReachesOnlyTheLoopback(t *testing.T) {
	for _, args := range [][]string{
		{hookCommand},
		{hookCommand, "http://127.0.0.1:1", "set", "name"},
		{hookCommand, "http://127.0.0.1:1", "delete", "name", "value"},
		{hookCommand, "http://127.0.0.1:1", "update", "name"},
		{hookCommand, "https://127.0.0.1:1", "delete", "name"},
		{hookCommand, "http://dns.example.net", "delete", "name"},
		{hookCommand, "http://127.0.0.1:1", "delete", "name"}, // nothing listens there
	} {
		if code := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); code != liveconf.ExitUsage {
			t.Errorf("run(%q) = %d, want %d", args, code, liveconf.ExitUsage)
		}
	}
}

func TestAReportThatCannotBeWritten(t *testing.T) {
	if code := run(context.Background(), []string{"-report", filepath.Join(t.TempDir(), "missing", "r.json")}, &bytes.Buffer{}, &bytes.Buffer{}); code != liveconf.ExitIncomplete {
		t.Errorf("exit %d, want %d", code, liveconf.ExitIncomplete)
	}
}
