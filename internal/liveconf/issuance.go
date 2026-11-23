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
	reasonCTVerify = "the inclusion of the certificate in the logs and the snapshot of Certificate Transparency need -ct-verify, which this version of the tool does not have yet"
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
}

// outcome is how an order ended: with a certificate, refused by the CA with a problem type,
// or without an answer.
type outcome struct {
	chain [][]byte
	key   *ecdsa.PublicKey
	// problem is the ACME problem type without its prefix, or a word of the tool.
	problem string
	// unreachable is the kind of a network failure.
	unreachable string
}

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

// play orders the certificate, the wildcard name and the certificate for an account that was
// not reported, and checks the SCTs.
func (is *issuing) play(ctx context.Context, own *acme.Client) error {
	got, err := is.order(ctx, own, is.name)
	if err != nil {
		return err
	}
	is.judgeIssue(got)
	wild, err := is.order(ctx, own, "*."+is.name)
	if err != nil {
		return err
	}
	is.judgeRefusal(CheckIssuanceWildcard, "an order for the wildcard name", wild)
	foreign, _, rerr := is.register(ctx)
	if rerr != nil {
		is.s.r.incomplete("the CA cannot be reached (" + classify(rerr).kind + ") for a second account")
	} else {
		other, err := is.order(ctx, foreign, is.name)
		if err != nil {
			return err
		}
		is.judgeRefusal(CheckIssuanceForeign, "an order of an account that was not reported", other)
	}
	is.checkSCTs(ctx, got)
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

// order asks for a certificate for the identifier through DNS-01, with the key authorization
// published through the operator's challenge endpoint. Only a failure of the operator is an error.
func (is *issuing) order(ctx context.Context, c *acme.Client, id string) (outcome, error) {
	ctx, cancel := context.WithTimeout(ctx, is.s.r.env.Timing.Slow)
	defer cancel()
	o, err := c.AuthorizeOrder(ctx, acme.DomainIDs(id))
	if err != nil {
		return failed(err), nil
	}
	for _, u := range o.AuthzURLs {
		ended, err := is.authorize(ctx, c, u)
		if err != nil || ended != nil {
			return derefOutcome(ended), err
		}
	}
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	csr := must(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{id}}, key))
	chain, _, err := c.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	if err != nil {
		return failed(err), nil
	}
	return outcome{chain: chain, key: &key.PublicKey}, nil
}

func derefOutcome(o *outcome) outcome {
	if o == nil {
		return outcome{}
	}
	return *o
}

// authorize completes one authorization; a non-nil outcome ends the order.
func (is *issuing) authorize(ctx context.Context, c *acme.Client, u string) (*outcome, error) {
	z, err := c.GetAuthorization(ctx, u)
	if err != nil {
		o := failed(err)
		return &o, nil
	}
	if z.Status == acme.StatusValid {
		return nil, nil
	}
	i := slices.IndexFunc(z.Challenges, func(ch *acme.Challenge) bool { return ch.Type == "dns-01" })
	if i < 0 {
		return &outcome{problem: problemNoDNS01}, nil
	}
	chal := z.Challenges[i]
	value := must(c.DNS01ChallengeRecord(chal.Token))
	_, err = is.s.c.Challenge(ctx, is.b.id, is.b.paired.Installation.ACMEChallenge, []string{value})
	name, fatal := apiName(err)
	switch {
	case fatal != nil:
		return nil, fatal
	case undecided(name):
		return &outcome{problem: "operator-" + name}, nil
	case err != nil:
		return &outcome{problem: problemChallengeRefused}, nil
	}
	// The gateway checks the record itself before it asks the CA to validate (RELAY-v0 section
	// 5.6). The end of the tool's own time limit is no failure of the operator.
	if err := is.s.dns.waitTXT(ctx, "_acme-challenge."+z.Identifier.Value, value); err != nil {
		if ctx.Err() != nil {
			return &outcome{unreachable: kindTimeout}, nil
		}
		return &outcome{problem: problemNotVisible}, nil
	}
	if _, err := c.Accept(ctx, chal); err != nil {
		o := failed(err)
		return &o, nil
	}
	if _, err := c.WaitAuthorization(ctx, u); err != nil {
		o := failed(err)
		return &o, nil
	}
	return nil, nil
}

// failed classifies an error of the ACME client by its problem type, which the tool shows
// only as a short word.
func failed(err error) outcome {
	var authz *acme.AuthorizationError
	var problem *acme.Error
	var ord *acme.OrderError
	switch {
	case errors.As(err, &authz):
		for _, e := range authz.Errors {
			if errors.As(e, &problem) {
				return outcome{problem: problemName(problem.ProblemType)}
			}
		}
		return outcome{problem: "invalid-authorization"}
	case errors.As(err, &problem):
		return outcome{problem: problemName(problem.ProblemType)}
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

// judgeIssue judges the order of the reported account: it must give a certificate for the
// standard name with the tool's key.
func (is *issuing) judgeIssue(o outcome) {
	switch {
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
		is.s.rec(CheckIssuanceIssue, "the CA refused the reported account because of the CAA records it sees (caa)")
	case o.problem == "unauthorized" || o.problem == "incorrectResponse":
		is.s.rec(CheckIssuanceIssue, "the CA did not find the challenge value that the operator published ("+o.problem+")")
	case o.problem == problemChallengeRefused:
		is.s.rec(CheckIssuanceIssue, "the operator refused the challenge value of the order")
	case o.problem == problemNotVisible:
		is.s.rec(CheckIssuanceIssue, "the challenge value did not show on the name servers of the name domain")
	default:
		is.s.r.incomplete(fmt.Sprintf("the CA refused the order of the reported account (%s), so the issuance could not be judged", o.problem))
	}
}

// judgeRefusal judges an order that the CA has to refuse because of the CAA records. A refusal
// for another reason decides nothing, because a CA checks CAA only after the validation.
func (is *issuing) judgeRefusal(id, what string, o outcome) {
	switch {
	case len(o.chain) > 0:
		is.s.rec(id, "the CA issued a certificate for "+what)
	case o.problem == "caa":
		is.s.rec(id, "")
	case o.unreachable != "":
		is.s.r.incomplete("the CA cannot be reached (" + o.unreachable + ") for " + what)
	default:
		is.s.r.incomplete(fmt.Sprintf("the CA refused %s for another reason than CAA (%s), so the refusal could not be judged", what, o.problem))
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
	r.incomplete(reasonCTVerify)
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
