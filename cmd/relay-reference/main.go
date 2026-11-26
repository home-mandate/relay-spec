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
//
// For the live runs before a release, the class issuance runs against a real CA (live.go). They
// are the maintainers' proof that the test tool and the reference hold against a real CA; an
// operator tests its own operation with relay-conformance:
//
//	relay-reference -live staging|production -zone <delegated zone> -dns-listen <address>...
//	                -ns-address <address>... -state <directory> -report <file>
//	relay-reference -ct-verify <file of a production run> -report <file>
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
	"strings"
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

// runLimit bounds the whole run against the reference; liveLimit a live run.
const (
	runLimit  = 10 * time.Minute
	liveLimit = 60 * time.Minute
)

// hookCommand is the first argument with which the command calls itself as the DNS hook.
const hookCommand = "dns-hook"

const usage = `usage: relay-reference -report <file>
       relay-reference -live staging|production -zone <zone> -dns-listen <address>...
                       -ns-address <address>... -state <directory> -report <file>
       relay-reference -ct-verify <file of a production run> -report <file>`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// listenList collects the repeatable -dns-listen.
type listenList []string

func (l *listenList) String() string { return fmt.Sprint(*l) }
func (l *listenList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// addrList collects the repeatable -ns-address.
type addrList []netip.Addr

func (l *addrList) String() string { return fmt.Sprint(*l) }
func (l *addrList) Set(v string) error {
	a, err := netip.ParseAddr(v)
	if err != nil {
		return err
	}
	*l = append(*l, a)
	return nil
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
	flags.SetOutput(io.Discard)
	reportPath := flags.String("report", "", "write the report as JSON to this file")
	var o liveOptions
	flags.StringVar(&o.env, "live", "", "staging or production: the class issuance against Let's Encrypt")
	flags.StringVar(&o.zone, "zone", "", "the delegated zone the live run serves")
	flags.Var((*listenList)(&o.listen), "dns-listen", "address of the public DNS of the live run (repeatable)")
	flags.Var((*addrList)(&o.ns), "ns-address", "address of ns1.<zone> as the glue has it (repeatable)")
	flags.StringVar(&o.stateDir, "state", "", "directory for the state of a live run")
	ctVerify := flags.String("ct-verify", "", "file of a production run to complete")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || *reportPath == "" || (o.env != "" && *ctVerify != "") {
		fmt.Fprintln(stderr, usage)
		return liveconf.ExitUsage
	}
	var res liveconf.Result
	switch {
	case *ctVerify != "":
		if o.set() {
			fmt.Fprintln(stderr, usage)
			return liveconf.ExitUsage
		}
		res = liveconf.ExecuteCTVerify(ctx, liveconf.Settings{CTVerifyPath: *ctVerify, Version: version})
	case o.env != "":
		if err := o.check(); err != nil {
			fmt.Fprintln(stderr, "relay-reference:", err)
			return liveconf.ExitUsage
		}
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintln(stderr, "relay-reference:", err)
			return liveconf.ExitIncomplete
		}
		ctx, cancel := context.WithTimeout(ctx, liveLimit)
		defer cancel()
		res = runLive(ctx, self, o, nil)
	default:
		if o.set() {
			fmt.Fprintln(stderr, usage)
			return liveconf.ExitUsage
		}
		var code int
		if res, code = runReference(ctx); code != 0 {
			fmt.Fprintln(stderr, "relay-reference: no directory for the state")
			return code
		}
	}
	return finish(res, *reportPath, stdout, stderr)
}

// runReference runs every class against the reference in a temporary directory.
func runReference(ctx context.Context) (liveconf.Result, int) {
	self, err := os.Executable()
	if err != nil {
		return liveconf.Result{}, liveconf.ExitIncomplete
	}
	state, err := os.MkdirTemp("", "relay-reference-")
	if err != nil {
		return liveconf.Result{}, liveconf.ExitIncomplete
	}
	defer os.RemoveAll(state)
	ctx, cancel := context.WithTimeout(ctx, runLimit)
	defer cancel()
	return runAgainstReference(ctx, self, filepath.Join(state, "state.json")), 0
}

// finish prints the result and writes the report.
func finish(res liveconf.Result, reportPath string, stdout, stderr io.Writer) int {
	if res.Report.Spec != "" {
		liveconf.Summarize(stdout, res.Report)
	}
	if res.Message != "" {
		fmt.Fprintln(stderr, strings.ReplaceAll(res.Message, "relay-conformance -ct-verify", "relay-reference -ct-verify"))
	}
	if res.Report.Spec == "" {
		return res.Exit
	}
	if err := writeReport(reportPath, res.Report); err != nil {
		fmt.Fprintln(stderr, "relay-reference: write the report:", err)
		return liveconf.ExitIncomplete
	}
	return res.Exit
}

// referenceTiming is DefaultTiming made small for the reference, which answers at once.
func referenceTiming() liveconf.Timing {
	return liveconf.Timing{
		Request: 5 * time.Second, Slow: 10 * time.Second, Hook: 5 * time.Second, Source: 5 * time.Second, SourcePause: 20 * time.Millisecond, Visible: 2 * time.Second, Poll: 20 * time.Millisecond,
		Cleanup: 5 * time.Second, RetryBudget: 300 * time.Millisecond, RetryUnit: 10 * time.Millisecond, TTLUnit: 10 * time.Millisecond,
		Tunnel: 3 * time.Second, Close: 2 * time.Second, Slack: 150 * time.Millisecond, ControlWindow: 120 * time.Millisecond, Deny: 600 * time.Millisecond,
	}
}

// startReference starts the reference operator and relay with the zones, and returns the
// environment and settings of a run against it, the reference CA included, and a stop function.
func startReference(self, statePath string, cfg refop.Config) (*refop.Running, liveconf.Env, liveconf.Settings, func()) {
	rl := refrelay.New(refrelay.Config{Host: "tunnel." + refop.DefaultOperator, AnnouncePins: true, TokenValidity: 400 * time.Millisecond})
	cfg.Relay = rl
	r := refop.Serve(cfg)
	base, stopHook := r.Operator.DNS().Control()
	env := liveconf.Env{
		Net:     netguard.Options{Policy: func(a netip.Addr) bool { return netguard.Allowed(a) || a.IsLoopback() }, Remap: r.Remap, Lookup: r.Lookup},
		NS:      r.NS,
		Roots:   r.Roots,
		Timing:  referenceTiming(),
		Unpair:  liveconf.UnpairInstallation,
		CAs:     []liveconf.CA{{Identity: refca.Identity, Production: caEndpoint(r), Staging: caEndpoint(r)}},
		LogList: func(context.Context) (*ctlog.List, error) { return r.Operator.CA().LogList(), nil },
		Sources: liveconf.CTSources{CertSpotter: r.Operator.CA().CertSpotter(), CrtSh: r.Operator.CA().CrtSh()},
	}
	tester := cfg.TesterZone
	if tester == "" {
		tester = refop.DefaultTesterZone
	}
	s := liveconf.Settings{
		Operator:  refop.DefaultOperator,
		Codes:     refop.DefaultCodes,
		OwnDomain: "home." + tester,
		DNSHook:   self + " " + hookCommand + " " + base,
		StatePath: statePath,
		Version:   version,
		// The reference CA plays the production environment of a CA, with its own logs.
		ACMEProduction: true,
	}
	return r, env, s, func() { stopHook(); _ = r.Close() }
}

// runAgainstReference starts the reference and runs every class against it, as
// cmd/relay-conformance/reference_test.go does: the same checks, with the address filter
// opened for the loopback and the time values made small.
func runAgainstReference(ctx context.Context, self, statePath string) liveconf.Result {
	_, env, s, stop := startReference(self, statePath, refop.Config{})
	defer stop()
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
