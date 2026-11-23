// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/liveconf"
	"github.com/home-mandate/relay-spec/internal/netguard"
	"github.com/home-mandate/relay-spec/internal/refca"
	"github.com/home-mandate/relay-spec/internal/refop"
	"github.com/home-mandate/relay-spec/internal/refrelay"
)

// TestHookHelper is the DNS hook of these tests: the test binary, called with
// "-- hookhelper <control URL> set|delete <name> [<value>]". It sets and removes the TXT record in
// the reference DNS through its control endpoint, as a hook does at a DNS provider.
func TestHookHelper(t *testing.T) {
	args := os.Args
	for i, a := range args {
		if a != "--" {
			continue
		}
		args = args[i+1:]
		if len(args) < 4 || args[0] != "hookhelper" {
			return
		}
		q := url.Values{"name": {args[3]}}
		method := http.MethodDelete
		if args[2] == "set" {
			method = http.MethodPost
			q.Set("value", args[4])
		}
		req, _ := http.NewRequest(method, args[1]+"/txt?"+q.Encode(), nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			os.Exit(3)
		}
		os.Exit(0)
	}
}

// referenceExecutor runs the real flow against a reference operator and relay on the loopback:
// the same code as the command, with the address filter loosened for the loopback and the time
// values made small.
func referenceExecutor(t *testing.T, faults refrelay.Fault) (executor, []string, *refop.Running) {
	t.Helper()
	rl := refrelay.New(refrelay.Config{Host: "tunnel." + refop.DefaultOperator, Faults: faults, AnnouncePins: true, TokenValidity: 400 * time.Millisecond})
	r := refop.Serve(refop.Config{Relay: rl})
	t.Cleanup(func() { _ = r.Close() })
	base, stop := r.Operator.DNS().Control()
	t.Cleanup(stop)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hook := exe + " -test.run=^TestHookHelper$ -- hookhelper " + base
	env := liveconf.Env{
		Net:   netguard.Options{Policy: func(a netip.Addr) bool { return netguard.Allowed(a) || a.IsLoopback() }, Remap: r.Remap, Lookup: r.Lookup},
		NS:    r.NS,
		Roots: r.Roots,
		Timing: liveconf.Timing{
			Request: 5 * time.Second, Slow: 10 * time.Second, Hook: 5 * time.Second, Visible: 2 * time.Second, Poll: 20 * time.Millisecond,
			Cleanup: 5 * time.Second, RetryBudget: 300 * time.Millisecond, RetryUnit: 10 * time.Millisecond,
			Tunnel: 3 * time.Second, Close: 2 * time.Second, Slack: 150 * time.Millisecond, ControlWindow: 120 * time.Millisecond, Deny: 600 * time.Millisecond,
		},
		Unpair:  liveconf.UnpairInstallation,
		CAs:     []liveconf.CA{{Identity: refca.Identity, Production: caEndpoint(r), Staging: caEndpoint(r)}},
		LogList: func(context.Context) (*ctlog.List, error) { return r.Operator.CA().LogList(), nil },
		Sources: liveconf.CTSources{CertSpotter: r.Operator.CA().CertSpotter(), CrtSh: r.Operator.CA().CrtSh()},
	}
	ex := executor{
		run: func(ctx context.Context, s liveconf.Settings) liveconf.Result { return liveconf.RunWith(ctx, s, env) },
		cleanup: func(ctx context.Context, s liveconf.Settings) liveconf.Result {
			return liveconf.CleanupWith(ctx, s, env)
		},
		ctVerify: func(ctx context.Context, s liveconf.Settings) liveconf.Result {
			return liveconf.CTVerifyWith(ctx, s, env)
		},
	}
	return ex, []string{
		"-operator", refop.DefaultOperator, "-code", refop.DefaultCodes[0], "-code", refop.DefaultCodes[1],
		"-own-domain", "home." + refop.DefaultTesterZone, "-dns-hook", hook, "-acme-production",
	}, r
}

// caEndpoint is the ACME endpoint of the reference CA of the operator.
func caEndpoint(r *refop.Running) liveconf.Endpoint {
	return liveconf.Endpoint{Directory: r.Operator.CA().Directory(), AccountPrefix: r.Operator.CA().AccountPrefix()}
}

// TestTheCommandAgainstTheReference: through run, the clean reference exits 3 with a report that
// says every class but issuance conforms and that only the checks of -ct-verify are missing, and
// -ct-verify with the file of the run then exits 0 with a conformant report; a defect exits 1
// with the failed check in the report; neither the output nor the report holds an installation
// URL or a pairing code.
func TestTheCommandAgainstTheReference(t *testing.T) {
	for name, tt := range map[string]struct {
		faults    refrelay.Fault
		exit      int
		conforms  bool
		failedIDs []string
	}{
		"clean reference": {0, liveconf.ExitIncomplete, false, nil},
		"R1 TLS 1.2":      {refrelay.TLS12, 1, false, []string{"relay.tls"}},
	} {
		t.Run(name, func(t *testing.T) {
			ex, args, r := referenceExecutor(t, tt.faults)
			dir := t.TempDir()
			reportPath := filepath.Join(dir, "report.json")
			args = append(args, "-state", filepath.Join(dir, "state.json"), "-report", reportPath)
			var out, errOut bytes.Buffer
			code := run(context.Background(), args, func(string) string { return "" }, &out, &errOut, ex)
			if code != tt.exit {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.exit, out.String(), errOut.String())
			}
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var rep liveconf.Report
			if err := json.Unmarshal(data, &rep); err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, f := range rep.Failures {
				ids = append(ids, f.ID)
			}
			if rep.Spec != liveconf.SpecName || rep.Conforms != tt.conforms || strings.Join(ids, ",") != strings.Join(tt.failedIDs, ",") {
				t.Errorf("report: spec %q, conforms %v, failures %v", rep.Spec, rep.Conforms, ids)
			}
			for _, class := range liveconf.AllClasses {
				if c := rep.Classes[class]; c == nil || c.NotRun || (tt.failedIDs == nil && c.Conforms != (class != liveconf.ClassIssuance)) {
					t.Errorf("class %s: %+v", class, c)
				}
			}
			if tt.failedIDs == nil && (len(rep.Incomplete) != 2 || !strings.Contains(rep.Incomplete[0], "-ct-verify")) {
				t.Errorf("incomplete %v", rep.Incomplete)
			}
			if rep.Installations.Created != 2 || rep.Installations.Unpaired != 2 {
				t.Errorf("installations %+v", rep.Installations)
			}
			secrets := append([]string{"/enroll/installation/"}, refop.DefaultCodes...)
			for _, text := range []string{out.String(), errOut.String(), string(data)} {
				for _, secret := range secrets {
					if strings.Contains(text, secret) {
						t.Errorf("%q reached the output", secret)
					}
				}
			}
			if routes := r.Operator.Routes(); len(routes) != 0 {
				t.Errorf("%d names are still served", len(routes))
			}
			if tt.failedIDs == nil {
				completeWithCTVerify(t, ex, dir)
			}
		})
	}
}

// completeWithCTVerify runs -ct-verify with the file of the run in dir: the report of the whole
// run conforms.
func completeWithCTVerify(t *testing.T, ex executor, dir string) {
	t.Helper()
	reportPath := filepath.Join(dir, "report-ct.json")
	var out, errOut bytes.Buffer
	args := []string{"-ct-verify", filepath.Join(dir, "state.ct.json"), "-report", reportPath}
	if code := run(context.Background(), args, func(string) string { return "" }, &out, &errOut, ex); code != liveconf.ExitConforms {
		t.Fatalf("-ct-verify: exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	var rep liveconf.Report
	if err := json.Unmarshal(must(os.ReadFile(reportPath)), &rep); err != nil || !rep.Conforms || rep.CTVerified == "" {
		t.Errorf("report after -ct-verify: %v, %+v", err, rep)
	}
	for _, class := range liveconf.AllClasses {
		if c := rep.Classes[class]; c == nil || !c.Conforms {
			t.Errorf("class %s: %+v", class, c)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
