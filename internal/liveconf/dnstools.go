// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"errors"
	"net"
	"slices"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/relay-spec/internal/dnsq"
	"github.com/home-mandate/relay-spec/internal/netguard"
)

var errNotVisible = errors.New("the record does not show on all name servers of its zone in time")

// dnsTools asks the authoritative name servers of zones.
type dnsTools struct {
	res    *dnsq.Resolver
	timing Timing
}

func newDNSTools(env Env) *dnsTools {
	lookupNS := env.NS
	if lookupNS == nil {
		lookupNS = systemNS
	}
	return &dnsTools{timing: env.Timing, res: &dnsq.Resolver{Dialer: netguard.New(env.Net), NS: lookupNS, Timeout: env.Timing.Request}}
}

// answered is the answer of one name server, or the reason it gave none.
type answered struct {
	server dnsq.Server
	answer dnsq.Answer
	err    error
}

// ask asks every server; an error of one server does not stop the others.
func (d *dnsTools) ask(ctx context.Context, servers []dnsq.Server, name string, typ dnsmessage.Type) []answered {
	out := make([]answered, len(servers))
	for i, s := range servers {
		a, err := d.res.Ask(ctx, s, name, typ)
		out[i] = answered{server: s, answer: a, err: err}
	}
	return out
}

// waitTXT waits until every name server of the zone of name shows exactly the TXT value, or,
// for an empty want, no TXT record.
func (d *dnsTools) waitTXT(ctx context.Context, name, want string) error {
	_, err := d.waitTexts(ctx, name, texts(want))
	return err
}

// waitTexts waits until every name server of the zone of name shows exactly the TXT values, in
// any order, and returns the longest TTL of their records.
func (d *dnsTools) waitTexts(ctx context.Context, name string, want []string) (uint32, error) {
	deadline := time.Now().Add(d.timing.Visible)
	for {
		if ttl, ok := d.textsAre(ctx, name, want); ok {
			return ttl, nil
		}
		if time.Now().After(deadline) {
			return 0, errNotVisible
		}
		if err := sleep(ctx, d.timing.Poll); err != nil {
			return 0, err
		}
	}
}

func (d *dnsTools) textsAre(ctx context.Context, name string, want []string) (uint32, bool) {
	_, servers, err := d.res.Zone(ctx, name)
	if err != nil {
		return 0, false
	}
	var ttl uint32
	for _, a := range d.ask(ctx, servers, name, dnsq.TypeTXT) {
		if a.err != nil || a.answer.RCode > dnsmessage.RCodeNameError || !onlyTexts(a.answer, want) {
			return 0, false
		}
		for _, r := range a.answer.Records {
			if r.Type == dnsq.TypeTXT {
				ttl = max(ttl, r.TTL)
			}
		}
	}
	return ttl, true
}

// texts is the one value, or none for an empty value.
func texts(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func onlyText(a dnsq.Answer, want string) bool { return onlyTexts(a, texts(want)) }

// onlyTexts reports whether the TXT records of the answer are exactly the values, in any order.
func onlyTexts(a dnsq.Answer, want []string) bool {
	var found []string
	for _, r := range a.Records {
		if r.Type == dnsq.TypeTXT {
			found = append(found, r.Text)
		}
	}
	slices.Sort(found)
	return slices.Equal(found, slices.Sorted(slices.Values(want)))
}

// systemNS looks the name servers of a name up with the system's resolver.
func systemNS(ctx context.Context, name string) ([]string, error) {
	records, err := net.DefaultResolver.LookupNS(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Host
	}
	return out, nil
}
