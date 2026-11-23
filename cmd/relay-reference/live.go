// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/home-mandate/relay-spec/internal/liveconf"
	"github.com/home-mandate/relay-spec/internal/refdns"
	"github.com/home-mandate/relay-spec/internal/refop"
)

// Time values of a live run: the reference answers at once, a CA and the logs may not.
const (
	liveRequest = 30 * time.Second
	liveSlow    = 180 * time.Second
	liveCleanup = 2 * time.Minute
)

// liveOptions are the flags of a live run.
type liveOptions struct {
	env      string
	zone     string
	listen   []string
	ns       []netip.Addr
	stateDir string
}

// set reports whether any flag of a live run was given.
func (o liveOptions) set() bool {
	return o.env != "" || o.zone != "" || len(o.listen) > 0 || len(o.ns) > 0 || o.stateDir != ""
}

func (o liveOptions) check() error {
	switch {
	case o.env != "staging" && o.env != "production":
		return errors.New("-live is staging or production")
	case !liveconf.ValidDomain(o.zone):
		return errors.New("-zone must be a lower-case domain name")
	case len(o.listen) == 0 || len(o.ns) == 0 || o.stateDir == "":
		return errors.New("a live run needs -dns-listen, -ns-address and -state")
	}
	info, err := os.Stat(o.stateDir)
	if err != nil || !info.IsDir() {
		return errors.New("-state must be a directory")
	}
	return nil
}

// runLive runs every class against the reference operator, with its name domain and the zone of
// the tester below the delegated zone, which a public DNS serves for the duration of the run,
// and the class issuance against Let's Encrypt (RELAY-v0 section 8.3). adjust, if set, changes
// the environment before the run; tests put the reference CA back with it.
func runLive(ctx context.Context, self string, o liveOptions, adjust func(*liveconf.Env, *refop.Running)) liveconf.Result {
	cfg := refop.Config{NameDomain: "homes." + o.zone, TesterZone: "tester." + o.zone}
	r, env, s, stop := startReference(self, filepath.Join(o.stateDir, "state.json"), cfg)
	defer stop()
	pub, err := r.Operator.DNS().ServePublic(refdns.PublicConfig{Apex: o.zone, Listen: o.listen, NSAddrs: o.ns})
	if err != nil {
		return liveconf.Result{Exit: liveconf.ExitIncomplete, Message: "relay-reference: the public DNS cannot listen: " + err.Error()}
	}
	defer pub.Close()
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	roots.AddCert(r.RootCA)
	env.Roots = roots
	env.CAs, env.LogList, env.Sources = liveconf.DefaultCAs, nil, liveconf.DefaultSources
	env.Timing.Request, env.Timing.Slow, env.Timing.Cleanup = liveRequest, liveSlow, liveCleanup
	s.ACMEProduction = o.env == "production"
	if adjust != nil {
		adjust(&env, r)
	}
	return liveconf.RunWith(ctx, s, env)
}
