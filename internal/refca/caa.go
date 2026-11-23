// SPDX-License-Identifier: Apache-2.0

package refca

import (
	"context"
	"slices"
	"strings"

	"github.com/home-mandate/relay-spec/internal/dnsq"
)

// criticalFlag is the issuer critical flag of a CAA record (RFC 8659 section 4.1).
const criticalFlag = 128

// knownTags are the property tags the CA understands.
var knownTags = []string{"issue", "issuewild", "iodef"}

// permits reports whether the CAA records let the CA issue for the name (a wildcard name if
// wildcard is set) to the account, validated with dns-01: the relevant record set is the first
// one found going up from the name (RFC 8659 section 3); for a wildcard name the issuewild
// properties count if there are any, else the issue properties, and for another name the issue
// properties (section 4.3); without such properties issuance is not restricted; a property permits the CA if its
// issuer domain name is the CA's and its parameters accounturi and validationmethods, if
// present, name the account and dns-01 (RFC 8657). A critical property that the CA does not
// know forbids issuance.
func (c *CA) permits(ctx context.Context, name string, wildcard bool, accountURI string) (bool, error) {
	set, err := c.relevantSet(ctx, name)
	if err != nil {
		return false, err
	}
	var issue, issuewild []string
	for _, r := range set {
		tag := strings.ToLower(r.Tag)
		if r.Flags&criticalFlag != 0 && !slices.Contains(knownTags, tag) {
			return false, nil
		}
		switch tag {
		case "issue":
			issue = append(issue, r.Value)
		case "issuewild":
			issuewild = append(issuewild, r.Value)
		}
	}
	values := issue
	if wildcard && len(issuewild) > 0 && !c.cfg.Faults.Has(IgnoreIssuewild) {
		values = issuewild
	}
	if len(values) == 0 {
		// No property restricts issuance for this name (issuewild alone does not restrict a
		// name that is no wildcard, RFC 8659 section 4.3).
		return true, nil
	}
	return slices.ContainsFunc(values, func(v string) bool { return c.permittedBy(v, accountURI) }), nil
}

func (c *CA) permittedBy(value, accountURI string) bool {
	parsed, err := dnsq.ParseIssue(value)
	if err != nil || parsed.Domain != Identity {
		return false
	}
	if acct, ok := parsed.Param("accounturi"); ok && acct != accountURI && !c.cfg.Faults.Has(IgnoreAccountURI) {
		return false
	}
	if methods, ok := parsed.Param("validationmethods"); ok && !slices.Contains(strings.Split(methods, ","), "dns-01") {
		return false
	}
	return true
}

// relevantSet returns the CAA records of the name or of its closest ancestor that has any.
func (c *CA) relevantSet(ctx context.Context, name string) ([]dnsq.CAA, error) {
	for n := name; strings.Contains(n, "."); _, n, _ = strings.Cut(n, ".") {
		set, err := c.cfg.DNS.CAA(ctx, n)
		if err != nil {
			return nil, err
		}
		if len(set) > 0 {
			return set, nil
		}
	}
	return nil, nil
}
