// SPDX-License-Identifier: Apache-2.0

package refop

import (
	"context"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/relay-spec/internal/dnsq"
	"github.com/home-mandate/relay-spec/internal/refca"
	"github.com/home-mandate/relay-spec/internal/refdns"
)

// caView is the DNS of the operator as the reference CA sees it: the records of the first name
// server, unless a fault makes the operator answer the CA otherwise (a split horizon).
type caView struct{ o *Operator }

func (v caView) records(name string, typ dnsmessage.Type) []dnsmessage.Resource {
	if !v.o.dns.Covers(name) {
		return nil
	}
	return v.o.dns.Lookup(0, name, typ)
}

// TXT returns the TXT values of the name.
func (v caView) TXT(_ context.Context, name string) ([]string, error) {
	if v.o.cfg.Faults.Has(CASeesNoChallenge) && strings.HasPrefix(name, challengeAt) {
		return nil, nil
	}
	var out []string
	for _, rr := range v.records(name, refdns.TypeTXT) {
		out = append(out, strings.Join(rr.Body.(*dnsmessage.TXTResource).TXT, ""))
	}
	return out, nil
}

// CAA returns the CAA records of the name. With CASeesOtherCAA the CA sees, for a standard
// name with an account in force, a record that permits it without naming the account.
func (v caView) CAA(_ context.Context, name string) ([]dnsq.CAA, error) {
	var out []dnsq.CAA
	for _, rr := range v.records(name, refdns.TypeCAA) {
		caa, err := dnsq.ParseCAA(rr.Body.(*dnsmessage.UnknownResource).Data)
		if err != nil {
			continue
		}
		if v.o.cfg.Faults.Has(CASeesOtherCAA) && caa.Tag == "issue" && strings.Contains(caa.Value, "accounturi=") {
			caa.Value = refca.Identity
		}
		out = append(out, caa)
	}
	return out, nil
}
