// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/crypto/acme"

	"github.com/home-mandate/relay-spec/internal/ctlog"
)

// CA is a CA with the ACME endpoints that the class issuance uses (RELAY-v0 section 8.3).
type CA struct {
	// Identity is the caa_identity of the CA.
	Identity string
	// Production issues real certificates; Staging is the test environment of the CA.
	Production, Staging Endpoint
}

// Endpoint is an ACME environment of a CA: its directory and the form of its account URIs.
type Endpoint struct {
	Directory     string
	AccountPrefix string
}

// DefaultCAs are the CAs of cas.md; a test compares them with that file.
var DefaultCAs = []CA{{
	Identity: "letsencrypt.org",
	Production: Endpoint{Directory: "https://acme-v02.api.letsencrypt.org/directory",
		AccountPrefix: "https://acme-v02.api.letsencrypt.org/acme/acct/"},
	Staging: Endpoint{Directory: "https://acme-staging-v02.api.letsencrypt.org/directory",
		AccountPrefix: "https://acme-staging-v02.api.letsencrypt.org/acme/acct/"},
}}

// Why the class issuance cannot make a run conformant.
const (
	reasonNoCA     = "acme_cas lists no CA whose ACME endpoints the tool knows, so the class issuance was not run"
	reasonStaging  = "Certificate Transparency is checked only against the production environment of the CA (-acme-production)"
	reasonCTVerify = "the inclusion of the certificate in the logs and the snapshot of Certificate Transparency are checked by -ct-verify with the file of this run"
	problemPrefix  = "urn:ietf:params:acme:error:"
	maxProblemName = 40
)

func runIssuance(ctx context.Context, r *run) error { return r.playScript(ctx) }

func (s *script) wantIssuance() bool { return s.r.selected(ClassIssuance) }

// caFor returns the first CA of acme_cas that the environment knows, with the endpoint of the run.
func (r *run) caFor(cas []string) (CA, Endpoint, bool) {
	for _, id := range cas {
		for _, ca := range r.env.CAs {
			if ca.Identity != id {
				continue
			}
			if r.s.ACMEProduction {
				return ca, ca.Production, true
			}
			return ca, ca.Staging, true
		}
	}
	return CA{}, Endpoint{}, false
}

// issuing is the class issuance for the second installation: a real account of the tool, which
// plays the gateway, and a second account that is never reported.
type issuing struct {
	s        *script
	b        *liveInst
	ep       Endpoint
	name     string
	accounts []*acme.Client
	// kept is the longest TTL of the challenge values published so far, in seconds.
	kept uint32
}

// outcome is how an order ended: with a certificate, refused by the CA with a problem type,
// or without an answer.
type outcome struct {
	chain [][]byte
	key   *ecdsa.PublicKey
	// problem is the ACME problem type without its prefix, or a word of the tool.
	problem string
	// detail is what the CA said about the problem.
	detail string
	// unreachable is the kind of a network failure.
	unreachable string
	// stopped is set when the tool's own time ended before it asked the CA.
	stopped bool
}

// reasonStopped is why an order that the tool stopped before asking the CA decides nothing.
const reasonStopped = "the time of the tool ended before the CA was asked for "

// Words of the tool for an order that did not reach the CA's decision.
const (
	problemChallengeRefused = "challenge-refused"
	problemNotVisible       = "challenge-not-visible"
	problemNoDNS01          = "no-dns-01"
)

// issuance reports a real account for the second installation, obtains a certificate for its
// standard name and orders what the CA has to refuse (RELAY-v0 section 8.3). It reports whether
// the account was reported, so that the installation gets no account that belongs to nobody.
// What the CA does is never fatal: the other classes go on.
func (s *script) issuance(ctx context.Context, b *liveInst) (bool, error) {
	ca, ep, ok := s.r.caFor(s.doc.ACMECAs)
	if !ok {
		s.r.incomplete(reasonNoCA)
		return false, nil
	}
	is := &issuing{s: s, b: b, ep: ep, name: b.paired.Installation.PublicName}
	defer is.deactivate()
	own, uri, err := is.register(ctx)
	if err != nil {
		s.r.incomplete("the CA cannot be reached (" + classify(err).kind + "), so the class issuance was not run")
		return false, nil
	}
	if !strings.HasPrefix(uri, ep.AccountPrefix) {
		s.r.note("the account URI of the CA does not have the prefix that cas.md lists")
	}
	_, err = s.c.ReportACME(ctx, b.id, uri, ca.Identity)
	name, fatal := apiName(err)
	switch {
	case fatal != nil:
		return true, fatal
	case undecided(name):
		s.r.incomplete("the operator could not take the report of the account (" + name + "), so the class issuance was not run")
		return true, nil
	case err != nil:
		s.rec(CheckIssuanceIssue, "the operator refused the report of the account ("+name+")")
		return true, nil
	}
	err = is.play(ctx, own)
	is.clearChallenge()
	return true, err
}

// undecided reports whether an error of the operator says nothing about its conformance: an
// error of its own server, or an answer the tool cannot read.
func undecided(name string) bool { return name == "server-internal" || name == "unexpected" }

// clearChallenge removes the challenge values, also after the limit of the run, within the
// time of the clean-up; unpairing removes them in any case (RELAY-v0 section 5.7).
func (is *issuing) clearChallenge() {
	ctx, cancel := context.WithTimeout(context.Background(), is.s.r.env.Timing.Cleanup)
	defer cancel()
	if _, err := is.s.c.Challenge(ctx, is.b.id, is.b.paired.Installation.ACMEChallenge, nil); err != nil {
		is.s.r.note("the challenge values of the class issuance could not be removed before unpairing")
	}
}

// play orders the certificate, then the wildcard name and the certificate for an account that
// was not reported together, and checks the SCTs (RELAY-v0 section 8.3).
func (is *issuing) play(ctx context.Context, own *acme.Client) error {
	got, err := is.orders(ctx, []wanted{{own, is.name}})
	if err != nil {
		return err
	}
	is.judgeIssue(got[0])
	if err := is.refusals(ctx, own); err != nil {
		return err
	}
	is.checkSCTs(ctx, got[0])
	return nil
}

// refusals orders the wildcard name and, with a second account that is never reported, the
// standard name; the CA has to refuse both.
func (is *issuing) refusals(ctx context.Context, own *acme.Client) error {
	const wildcard, foreign = "an order for the wildcard name", "an order of an account that was not reported"
	if is.kept > maxCacheWait {
		for _, what := range []string{wildcard, foreign} {
			is.s.r.incomplete(fmt.Sprintf("the challenge records have a TTL of %d seconds, more than the %d seconds the tool waits for a CA to forget them, so %s was not placed", is.kept, maxCacheWait, what))
		}
		return nil
	}
	checks, whats := []string{CheckIssuanceWildcard}, []string{wildcard}
	all := []wanted{{own, "*." + is.name}}
	if other, _, err := is.register(ctx); err != nil {
		is.s.r.incomplete("the CA cannot be reached (" + classify(err).kind + ") for a second account")
	} else {
		checks, whats, all = append(checks, CheckIssuanceForeign), append(whats, foreign), append(all, wanted{other, is.name})
	}
	got, err := is.orders(ctx, all)
	if err != nil {
		return err
	}
	for i, o := range got {
		is.judgeRefusal(checks[i], whats[i], o)
	}
	return nil
}

// register creates an account with a new key at the CA.
func (is *issuing) register(ctx context.Context) (*acme.Client, string, error) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	c := &acme.Client{Key: key, DirectoryURL: is.ep.Directory, HTTPClient: is.s.r.web.client}
	ctx, cancel := context.WithTimeout(ctx, is.s.r.env.Timing.Slow)
	defer cancel()
	acct, err := c.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		return nil, "", err
	}
	is.accounts = append(is.accounts, c)
	return c, acct.URI, nil
}

// deactivate deactivates the accounts of the run, also after an abort, within the time of the
// clean-up (RELAY-v0 section 8.3).
func (is *issuing) deactivate() {
	for _, c := range is.accounts {
		ctx, cancel := context.WithTimeout(context.Background(), is.s.r.env.Timing.Cleanup)
		_ = c.DeactivateReg(ctx)
		cancel()
	}
}

// failed classifies an error of the ACME client by its problem type, which the tool shows as a
// short word, and keeps what the CA said about it.
func failed(err error) outcome {
	var authz *acme.AuthorizationError
	var problem *acme.Error
	var ord *acme.OrderError
	switch {
	case errors.As(err, &authz):
		for _, e := range authz.Errors {
			if errors.As(e, &problem) {
				return outcome{problem: problemName(problem.ProblemType), detail: problem.Detail}
			}
		}
		return outcome{problem: "invalid-authorization"}
	case errors.As(err, &problem):
		return outcome{problem: problemName(problem.ProblemType), detail: problem.Detail}
	case errors.As(err, &ord):
		return outcome{problem: "invalid-order"}
	}
	return outcome{unreachable: classify(err).kind}
}

// problemName is an ACME problem type without its prefix, if it is a short word of letters.
func problemName(t string) string {
	name, ok := strings.CutPrefix(t, problemPrefix)
	if !ok || name == "" || len(name) > maxProblemName || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return "other"
	}
	return name
}

// cause is the problem of the outcome with what the CA said about it, quoted and cut.
func (o outcome) cause() string {
	if o.detail == "" {
		return o.problem
	}
	return o.problem + ": " + esc(o.detail)
}

// judgeIssue judges the order of the reported account: it must give a certificate for the
// standard name with the tool's key.
func (is *issuing) judgeIssue(o outcome) {
	switch {
	case o.stopped:
		is.s.r.incomplete(reasonStopped + "the order of the reported account")
	case o.unreachable != "":
		is.s.r.incomplete("the CA cannot be reached (" + o.unreachable + ") for the order of the reported account")
	case len(o.chain) > 0:
		leaf, err := x509.ParseCertificate(o.chain[0])
		switch {
		case err != nil:
			is.s.rec(CheckIssuanceIssue, "the CA sent a certificate that cannot be parsed")
		case !slices.Equal(leaf.DNSNames, []string{is.name}) || !o.key.Equal(leaf.PublicKey):
			is.s.rec(CheckIssuanceIssue, "the certificate is not for the standard name and the key of the order")
		default:
			is.s.rec(CheckIssuanceIssue, "")
		}
	case o.problem == "caa":
		is.s.rec(CheckIssuanceIssue, "the CA refused the reported account because of the CAA records it sees ("+o.cause()+")")
	case o.problem == "unauthorized" || o.problem == "incorrectResponse":
		is.s.rec(CheckIssuanceIssue, "the CA did not find the challenge value that the operator published ("+o.cause()+")")
	case o.problem == problemChallengeRefused:
		is.s.rec(CheckIssuanceIssue, "the operator refused the challenge value of the order")
	case o.problem == problemNotVisible:
		is.s.rec(CheckIssuanceIssue, "the challenge value did not show on the name servers of the name domain")
	default:
		is.s.r.incomplete(fmt.Sprintf("the CA refused the order of the reported account (%s), so the issuance could not be judged", o.cause()))
	}
}

// judgeRefusal judges an order that the CA has to refuse because of the CAA records. A refusal
// for another reason decides nothing, because a CA checks CAA only after the validation.
func (is *issuing) judgeRefusal(id, what string, o outcome) {
	switch {
	case o.stopped:
		is.s.r.incomplete(reasonStopped + what)
	case len(o.chain) > 0:
		is.s.rec(id, "the CA issued a certificate for "+what)
	case o.problem == "caa":
		is.s.rec(id, "")
	case o.unreachable != "":
		is.s.r.incomplete("the CA cannot be reached (" + o.unreachable + ") for " + what)
	default:
		is.s.r.incomplete(fmt.Sprintf("the CA refused %s for another reason than CAA (%s), so the refusal could not be judged", what, o.cause()))
	}
}

// checkSCTs checks the SCTs of the certificate in production; in the test environment of a CA
// the logs are in no public log list.
func (is *issuing) checkSCTs(ctx context.Context, o outcome) {
	r := is.s.r
	if !r.s.ACMEProduction {
		r.incomplete(reasonStaging)
		return
	}
	if len(o.chain) == 0 {
		return
	}
	if len(o.chain) < 2 {
		r.incomplete("the CA sent no issuer certificate, so the SCTs could not be checked")
		return
	}
	leaf, err1 := x509.ParseCertificate(o.chain[0])
	issuer, err2 := x509.ParseCertificate(o.chain[1])
	if err1 != nil || err2 != nil || leaf.CheckSignatureFrom(issuer) != nil {
		r.incomplete("the CA sent no certificate of its issuer after the certificate, so the SCTs could not be checked")
		return
	}
	if is.s.seen[CheckIssuanceIssue] && !is.s.r.failedCheck(CheckIssuanceIssue) {
		r.incomplete(reasonCTVerify)
		r.ct = &ctCertificate{leaf: leaf, issuer: issuer, name: is.name}
	}
	list, err := r.logList(ctx)
	if err != nil {
		r.incomplete("the log list could not be fetched and verified, so the SCTs were not checked")
		return
	}
	is.s.rec(CheckIssuanceSCT, strings.Join(ctlog.Check(leaf, issuer, list), "; "))
}

// logList returns the log list of the environment, or the signed list of Google.
func (r *run) logList(ctx context.Context) (*ctlog.List, error) {
	if r.env.LogList != nil {
		return r.env.LogList(ctx)
	}
	return fetchLogList(ctx, r.web, ctlog.ListURL, ctlog.SignatureURL, ctlog.GoogleKey())
}

// fetchLogList fetches the log list and its signature, checks the signature with the key and
// parses the list (RELAY-v0 section 8.3).
func fetchLogList(ctx context.Context, w *Web, listURL, sigURL string, key *rsa.PublicKey) (*ctlog.List, error) {
	list, err := w.get(ctx, listURL, ctlog.MaxListBytes)
	if err != nil {
		return nil, err
	}
	sig, err := w.get(ctx, sigURL, ctlog.MaxSignatureBytes)
	if err != nil {
		return nil, err
	}
	if list.Status != http.StatusOK || sig.Status != http.StatusOK || list.Over || sig.Over {
		return nil, ctlog.ErrList
	}
	if err := ctlog.VerifySignature(list.Body, sig.Body, key); err != nil {
		return nil, err
	}
	return ctlog.ParseList(list.Body)
}
