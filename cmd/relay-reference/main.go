// SPDX-License-Identifier: Apache-2.0

// Command relay-reference runs the live test of relay-conformance (RELAY-v0 Section 8) against
// the reference operator, relay and DNS of this repository, which it starts on the loopback,
// and writes the report:
//
//	relay-reference -report <file>
//
// A release attaches this report: it shows that the reference code of the release conforms to
// all five classes. The command reaches nothing but its own reference: it takes no operator, no
// pairing codes and no DNS hook, so the loopback addresses and the short time values it allows
// can never be used against a real operator. relay-conformance itself never allows them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/liveconf"
	"github.com/home-mandate/relay-spec/internal/netguard"
	"github.com/home-mandate/relay-spec/internal/refca"
	"github.com/home-mandate/relay-spec/internal/refop"
	"github.com/home-mandate/relay-spec/internal/refrelay"
)

// version is set at build time: -ldflags "-X main.version=<version>".
var version = "devel"

// runLimit bounds the whole run against the reference.
const runLimit = 10 * time.Minute

// hookCommand is the first argument with which the command calls itself as the DNS hook.
const hookCommand = "dns-hook"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == hookCommand {
		if err := dnsHook(ctx, args[1:]); err != nil {
			fmt.Fprintln(stderr, "relay-reference:", err)
			return liveconf.ExitUsage
		}
		return liveconf.ExitConforms
	}
	flags := flag.NewFlagSet("relay-reference", flag.ContinueOnError)
	flags.SetOutput(stderr)
	reportPath := flags.String("report", "", "write the report as JSON to this file")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || *reportPath == "" {
		fmt.Fprintln(stderr, "usage: relay-reference -report <file>")
		return liveconf.ExitUsage
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "relay-reference:", err)
		return liveconf.ExitIncomplete
	}
	state, err := os.MkdirTemp("", "relay-reference-")
	if err != nil {
		fmt.Fprintln(stderr, "relay-reference:", err)
		return liveconf.ExitIncomplete
	}
	defer os.RemoveAll(state)

	ctx, cancel := context.WithTimeout(ctx, runLimit)
	defer cancel()
	res := runAgainstReference(ctx, self, filepath.Join(state, "state.json"))
	liveconf.Summarize(stdout, res.Report)
	if res.Message != "" {
		fmt.Fprintln(stderr, res.Message)
	}
	if err := writeReport(*reportPath, res.Report); err != nil {
		fmt.Fprintln(stderr, "relay-reference: write the report:", err)
		return liveconf.ExitIncomplete
	}
	return res.Exit
}

// runAgainstReference starts the reference and runs every class against it, as
// cmd/relay-conformance/reference_test.go does: the same checks, with the address filter
// opened for the loopback and the time values made small.
func runAgainstReference(ctx context.Context, self, statePath string) liveconf.Result {
	rl := refrelay.New(refrelay.Config{Host: "tunnel." + refop.DefaultOperator, AnnouncePins: true, TokenValidity: 400 * time.Millisecond})
	r := refop.Serve(refop.Config{Relay: rl})
	defer r.Close()
	base, stop := r.Operator.DNS().Control()
	defer stop()
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
	s := liveconf.Settings{
		Operator:  refop.DefaultOperator,
		Codes:     refop.DefaultCodes,
		OwnDomain: "home." + refop.DefaultTesterZone,
		DNSHook:   self + " " + hookCommand + " " + base,
		StatePath: statePath,
		Version:   version,
		// The reference CA plays the production environment of a CA, with its own logs.
		ACMEProduction: true,
	}
	res := liveconf.RunWith(ctx, s, env)
	if res.CTFile == "" {
		return res
	}
	// The logs of the reference CA include at once, so the run is completed right away.
	return liveconf.CTVerifyWith(ctx, liveconf.Settings{CTVerifyPath: res.CTFile, Version: version}, env)
}

// caEndpoint is the ACME endpoint of the reference CA of the operator.
func caEndpoint(r *refop.Running) liveconf.Endpoint {
	return liveconf.Endpoint{Directory: r.Operator.CA().Directory(), AccountPrefix: r.Operator.CA().AccountPrefix()}
}

// dnsHook sets or removes the challenge TXT record in the reference DNS through its control
// endpoint, as a hook does at a DNS provider: <control URL> set <name> <value> | delete <name>.
func dnsHook(ctx context.Context, args []string) error {
	if len(args) < 3 || (args[1] == "set") != (len(args) == 4) || (args[1] != "set" && args[1] != "delete") {
		return errors.New("usage: relay-reference dns-hook <control URL> set <name> <value> | delete <name>")
	}
	control, err := url.Parse(args[0])
	if err != nil || control.Scheme != "http" || !isLoopback(control.Hostname()) {
		return errors.New("the control URL is not the reference DNS on the loopback")
	}
	q := url.Values{"name": {args[2]}}
	method := http.MethodDelete
	if args[1] == "set" {
		method = http.MethodPost
		q.Set("value", args[3])
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, args[0]+"/txt?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the reference DNS answered %s", resp.Status)
	}
	return nil
}

func isLoopback(host string) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func writeReport(path string, r liveconf.Report) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	return errors.Join(r.Write(f), f.Close())
}
