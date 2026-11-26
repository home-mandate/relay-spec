// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/liveconf"
	"github.com/home-mandate/relay-spec/internal/refca"
	"github.com/home-mandate/relay-spec/internal/refdns"
	"github.com/home-mandate/relay-spec/internal/refop"
)

const liveZone = "relay-test.example.com"

// soaOf asks the public DNS for the SOA of name and returns the rcode, or false without answer.
func soaOf(addr, name string) (dnsmessage.RCode, bool) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET})
	wire, _ := b.Finish()
	c, err := net.Dial("udp", addr)
	if err != nil {
		return 0, false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write(wire)
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	var m dnsmessage.Message
	if err != nil || m.Unpack(buf[:n]) != nil {
		return 0, false
	}
	return m.RCode, true
}

// backToReference puts the reference CA, its logs and sources back into a live environment, so
// that the test reaches no real CA, and makes the second of a TTL short; it also records the address of the public DNS and what it
// answers during the run.
func backToReference(t *testing.T, listen *string, seen *[]string) func(*liveconf.Env, *refop.Running, string) {
	return func(env *liveconf.Env, r *refop.Running, addr string) {
		*listen = addr
		if len(env.CAs) != 1 || env.CAs[0].Identity != "letsencrypt.org" || env.LogList != nil || env.Sources != liveconf.DefaultSources {
			t.Errorf("a live run does not use Let's Encrypt, the list of Google and the sources: %+v", env.CAs)
		}
		if env.Timing.TTLUnit != time.Second {
			t.Errorf("a live run waits out a TTL in units of %v", env.Timing.TTLUnit)
		}
		env.Timing.TTLUnit = time.Millisecond
		if env.Timing.Source != liveconf.DefaultTiming.Source || env.Timing.SourcePause != liveconf.DefaultTiming.SourcePause {
			t.Errorf("a live run gives the search sources %v and pauses %v", env.Timing.Source, env.Timing.SourcePause)
		}
		// A live run resolves names outside the reference, such as those of the CA, the logs and
		// the sources, with the system resolver; "localhost" stands for them here.
		if _, err := env.Net.Lookup(context.Background(), "localhost"); err != nil {
			t.Errorf("a live run cannot resolve a name outside the reference: %v", err)
		}
		ca := r.Operator.CA()
		ep := liveconf.Endpoint{Directory: ca.Directory(), AccountPrefix: ca.AccountPrefix()}
		env.CAs = []liveconf.CA{{Identity: refca.Identity, Production: ep, Staging: ep}}
		env.LogList = func(context.Context) (*ctlog.List, error) { return ca.LogList(), nil }
		env.Sources = liveconf.CTSources{CertSpotter: ca.CertSpotter(), CrtSh: ca.CrtSh()}
		for _, name := range []string{liveZone, "example.org"} {
			rcode, ok := soaOf(addr, name)
			if !ok {
				*seen = append(*seen, name+"=no answer")
				continue
			}
			*seen = append(*seen, name+"="+rcode.String())
		}
	}
}

// TestALiveRunServesTheZoneOnlyWhileItRuns: the run uses names below the delegated zone, which
// the public DNS answers for during the run and no longer afterwards.
func TestALiveRunServesTheZoneOnlyWhileItRuns(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			o := liveOptions{env: env, zone: liveZone, listen: []string{"127.0.0.1:0"}, ns: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, stateDir: t.TempDir()}
			if err := o.check(); err != nil {
				t.Fatal(err)
			}
			var listen string
			var seen []string
			res := runLive(context.Background(), self, o, backToReference(t, &listen, &seen))
			if len(res.Report.Failures) != 0 || res.Exit != liveconf.ExitIncomplete {
				t.Fatalf("exit %d (%s), failures %+v", res.Exit, res.Message, res.Report.Failures)
			}
			want := []string{liveZone + "=RCodeSuccess", "example.org=RCodeRefused"}
			if !slices.Equal(seen, want) {
				t.Errorf("the public DNS during the run: %v", seen)
			}
			if _, ok := soaOf(listen, liveZone); ok {
				t.Error("the public DNS still answers after the run")
			}
			_, err := os.Stat(filepath.Join(o.stateDir, "state.ct.json"))
			if (err == nil) != (env == "production") {
				t.Errorf("file for -ct-verify: %v", err)
			}
		})
	}
}

func TestLiveFlags(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "r.json")
	base := []string{"-live", "staging", "-zone", liveZone, "-dns-listen", "127.0.0.1:0", "-ns-address", "192.0.2.53", "-state", dir, "-report", report}
	for name, args := range map[string][]string{
		"unknown environment": {"-live", "test", "-zone", liveZone, "-dns-listen", "x", "-ns-address", "192.0.2.53", "-state", dir, "-report", report},
		"no zone":             {"-live", "staging", "-dns-listen", "x", "-ns-address", "192.0.2.53", "-state", dir, "-report", report},
		"no address":          {"-live", "staging", "-zone", liveZone, "-dns-listen", "x", "-state", dir, "-report", report},
		"no listen":           {"-live", "staging", "-zone", liveZone, "-ns-address", "192.0.2.53", "-state", dir, "-report", report},
		"bad address":         append(slices.Clone(base), "-ns-address", "nope"),
		"no directory":        {"-live", "staging", "-zone", liveZone, "-dns-listen", "x", "-ns-address", "192.0.2.53", "-state", filepath.Join(dir, "none"), "-report", report},
		"zone without -live":  {"-zone", liveZone, "-report", report},
		"live and ct-verify":  append(slices.Clone(base), "-ct-verify", "f.ct.json"),
		"ct-verify with zone": {"-ct-verify", "f.ct.json", "-zone", liveZone, "-report", report},
	} {
		if code := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); code != liveconf.ExitUsage {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	var errOut bytes.Buffer
	if code := run(context.Background(), []string{"-ct-verify", filepath.Join(dir, "none.ct.json"), "-report", report}, &bytes.Buffer{}, &errOut); code != liveconf.ExitUsage || !strings.Contains(errOut.String(), "-ct-verify") {
		t.Errorf("-ct-verify without a file: exit %d, %s", code, errOut.String())
	}
}

// TestALiveRunWithoutItsPortIsIncomplete: when the public DNS cannot listen, the run reaches no
// CA and ends incomplete.
func TestALiveRunWithoutItsPortIsIncomplete(t *testing.T) {
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	dir := t.TempDir()
	var errOut bytes.Buffer
	code := run(context.Background(), []string{"-live", "staging", "-zone", liveZone, "-dns-listen", busy.LocalAddr().String(),
		"-ns-address", "192.0.2.53", "-state", dir, "-report", filepath.Join(dir, "r.json")}, &bytes.Buffer{}, &errOut)
	if code != liveconf.ExitIncomplete || !strings.Contains(errOut.String(), "cannot listen") {
		t.Errorf("exit %d, %s", code, errOut.String())
	}
}

// TestTheLiveLookupAsksTheReferenceFirst: a name of the reference resolves there, a name the
// reference does not know goes to the system, and any other error of the reference stays.
func TestTheLiveLookupAsksTheReferenceFirst(t *testing.T) {
	refAddr, sysAddr := netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("192.0.2.1")
	broken := errors.New("broken")
	ref := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "ns1.example.net":
			return []netip.Addr{refAddr}, nil
		case "broken.example.net":
			return nil, broken
		}
		return nil, refdns.ErrNoSuchHost
	}
	var asked []string
	sys := func(_ context.Context, host string) ([]netip.Addr, error) {
		asked = append(asked, host)
		return []netip.Addr{sysAddr}, nil
	}
	lookup := liveLookup(ref, sys)
	if a, err := lookup(context.Background(), "ns1.example.net"); err != nil || a[0] != refAddr {
		t.Errorf("a name of the reference: %v %v", a, err)
	}
	if a, err := lookup(context.Background(), "acme-v02.api.letsencrypt.org"); err != nil || a[0] != sysAddr {
		t.Errorf("a name outside the reference: %v %v", a, err)
	}
	if _, err := lookup(context.Background(), "broken.example.net"); !errors.Is(err, broken) {
		t.Errorf("an error of the reference: %v", err)
	}
	if !slices.Equal(asked, []string{"acme-v02.api.letsencrypt.org"}) {
		t.Errorf("the system was asked for %v", asked)
	}
}
