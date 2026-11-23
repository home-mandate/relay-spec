// SPDX-License-Identifier: Apache-2.0

package refca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/dnsq"
	"github.com/home-mandate/relay-spec/internal/refca"
)

const name = "h.homes.example.org"

// zone is the CA's view of DNS in these tests.
type zone struct {
	mu   sync.Mutex
	txt  map[string][]string
	caa  map[string][]dnsq.CAA
	fail bool
}

func (z *zone) TXT(_ context.Context, n string) ([]string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.fail {
		return nil, errors.New("SERVFAIL")
	}
	return z.txt[n], nil
}

func (z *zone) CAA(_ context.Context, n string) ([]dnsq.CAA, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.fail {
		return nil, errors.New("SERVFAIL")
	}
	return z.caa[n], nil
}

func (z *zone) setTXT(n string, v ...string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.txt[n] = v
}

func (z *zone) setCAA(n string, v ...dnsq.CAA) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if v == nil {
		delete(z.caa, n)
		return
	}
	z.caa[n] = v
}

func (z *zone) setFail(fail bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.fail = fail
}

func issue(v string) dnsq.CAA { return dnsq.CAA{Tag: "issue", Value: v} }

func issuewild(v string) dnsq.CAA { return dnsq.CAA{Tag: "issuewild", Value: v} }

// world is a reference CA behind TLS and a client for it.
type world struct {
	ca     *refca.CA
	zone   *zone
	client *http.Client
	base   string
}

func newWorld(t *testing.T, faults refca.Fault) *world {
	t.Helper()
	z := &zone{txt: map[string][]string{}, caa: map[string][]dnsq.CAA{
		"homes.example.org": {issue(";"), issuewild(";")},
	}}
	ca := refca.New(refca.Config{DNS: z, Faults: faults})
	srv := httptest.NewUnstartedServer(ca.Handler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // the test server's certificate is not for the CA's host
	dir := ca.Directory()
	return &world{ca: ca, zone: z, client: &http.Client{Transport: transport}, base: dir[:strings.LastIndex(dir, "/")]}
}

func (w *world) account(t *testing.T) (*acme.Client, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &acme.Client{Key: key, DirectoryURL: w.ca.Directory(), HTTPClient: w.client}
	acct, err := c.Register(context.Background(), &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(acct.URI, w.ca.AccountPrefix()) {
		t.Fatalf("account %s, prefix %s", acct.URI, w.ca.AccountPrefix())
	}
	return c, acct.URI
}

func (w *world) permit(account string) {
	w.zone.setCAA(name, issue(refca.Identity+"; accounturi="+account+"; validationmethods=dns-01"), issuewild(";"))
}

// order asks for a certificate for the identifier through DNS-01 and returns the chain.
func (w *world) order(t *testing.T, c *acme.Client, id string, publish bool) ([][]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := c.AuthorizeOrder(ctx, acme.DomainIDs(id))
	if err != nil {
		return nil, err
	}
	for _, u := range o.AuthzURLs {
		z, err := c.GetAuthorization(ctx, u)
		if err != nil {
			return nil, err
		}
		if len(z.Challenges) != 1 || z.Challenges[0].Type != "dns-01" {
			t.Fatalf("challenges %+v", z.Challenges)
		}
		chal := z.Challenges[0]
		if publish {
			rec, _ := c.DNS01ChallengeRecord(chal.Token)
			w.zone.setTXT("_acme-challenge."+z.Identifier.Value, "other", rec)
		}
		if _, err := c.Accept(ctx, chal); err != nil {
			return nil, err
		}
		if _, err := c.WaitAuthorization(ctx, u); err != nil {
			return nil, err
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{id}}, key)
	der, _, err := c.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	return der, err
}

// problemType returns the ACME problem type of an error of the client, or "issued".
func problemType(err error) string {
	var ae *acme.AuthorizationError
	var e *acme.Error
	switch {
	case errors.As(err, &ae) && len(ae.Errors) > 0:
		return problemType(ae.Errors[0])
	case errors.As(err, &e):
		return strings.TrimPrefix(e.ProblemType, "urn:ietf:params:acme:error:")
	case err == nil:
		return "issued"
	}
	return "other: " + err.Error()
}

func TestTheCleanCAIssuesOnlyAsTheCAARecordsSay(t *testing.T) {
	w := newWorld(t, 0)
	a, acctA := w.account(t)
	b, _ := w.account(t)
	w.permit(acctA)

	der, err := w.order(t, a, name, true)
	if err != nil {
		t.Fatalf("the reported account: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der[0])
	issuer, _ := x509.ParseCertificate(der[1])
	if leaf.DNSNames[0] != name || leaf.CheckSignatureFrom(issuer) != nil {
		t.Errorf("leaf %v", leaf.DNSNames)
	}
	if p := ctlog.Check(leaf, issuer, w.ca.LogList()); len(p) != 0 {
		t.Errorf("SCTs: %v", p)
	}
	for what, tt := range map[string]struct {
		client  *acme.Client
		id      string
		publish bool
		want    string
	}{
		"an account that was not reported": {b, name, true, "caa"},
		"a wildcard":                       {a, "*." + name, true, "caa"},
		"without the TXT record":           {b, "y." + name, false, "unauthorized"},
	} {
		if _, err := w.order(t, tt.client, tt.id, tt.publish); problemType(err) != tt.want {
			t.Errorf("%s: %s, want %s", what, problemType(err), tt.want)
		}
	}
	if n := len(w.ca.Issued()); n != 1 {
		t.Errorf("%d certificates issued", n)
	}
}

func TestCAARecordsByRFC8659And8657(t *testing.T) {
	w := newWorld(t, 0)
	a, acct := w.account(t)
	for what, tt := range map[string]struct {
		records []dnsq.CAA
		id      string
		want    string
	}{
		"other methods only":        {[]dnsq.CAA{issue(refca.Identity + "; validationmethods=http-01")}, name, "caa"},
		"methods listed":            {[]dnsq.CAA{issue(refca.Identity + "; validationmethods=http-01,dns-01")}, name, "issued"},
		"no parameters":             {[]dnsq.CAA{issue(refca.Identity)}, name, "issued"},
		"another CA":                {[]dnsq.CAA{issue("ca.example.net")}, name, "caa"},
		"only iodef":                {[]dnsq.CAA{{Tag: "iodef", Value: "mailto:x@example.org"}}, name, "issued"},
		"a critical unknown tag":    {[]dnsq.CAA{issue(refca.Identity), {Flags: 128, Tag: "future", Value: "x"}}, name, "caa"},
		"a malformed issue":         {[]dnsq.CAA{issue(refca.Identity + "; =")}, name, "caa"},
		"issue for a wildcard":      {[]dnsq.CAA{issue(refca.Identity)}, "*." + name, "issued"},
		"issuewild for a wildcard":  {[]dnsq.CAA{issue(";"), issuewild(refca.Identity + "; accounturi=" + acct)}, "*." + name, "issued"},
		"another account":           {[]dnsq.CAA{issue(refca.Identity + "; accounturi=" + acct + "9")}, name, "caa"},
		"the issuer in upper case":  {[]dnsq.CAA{issue(strings.ToUpper(refca.Identity) + "; accounturi=" + acct)}, name, "issued"},
		"a name below a record":     {[]dnsq.CAA{issue(";")}, "x." + name, "caa"},
		"one of two records allows": {[]dnsq.CAA{issue("ca.example.net"), issue(refca.Identity)}, name, "issued"},
		"issuewild alone, no wild":  {[]dnsq.CAA{issuewild(";")}, name, "issued"},
		"issuewild alone, wild":     {[]dnsq.CAA{issuewild(";")}, "*." + name, "caa"},
	} {
		t.Run(what, func(t *testing.T) {
			w.zone.setCAA(name, tt.records...)
			if _, err := w.order(t, a, tt.id, true); problemType(err) != tt.want {
				t.Errorf("%s, want %s", problemType(err), tt.want)
			}
		})
	}
	t.Run("the apex decides when the name has no record", func(t *testing.T) {
		w.zone.setCAA(name)
		if _, err := w.order(t, a, name, true); problemType(err) != "caa" {
			t.Errorf("%s", problemType(err))
		}
	})
	t.Run("no record anywhere", func(t *testing.T) {
		if _, err := w.order(t, a, "h.unrelated.example", true); problemType(err) != "issued" {
			t.Errorf("%s", problemType(err))
		}
	})
	t.Run("a failed lookup", func(t *testing.T) {
		w.permit(acct)
		w.zone.setFail(true)
		defer w.zone.setFail(false)
		if _, err := w.order(t, a, name, false); problemType(err) != "dns" {
			t.Errorf("%s", problemType(err))
		}
	})
}

// TestEachFaultBreaksExactlyWhatItNames: each defect of the CA shows in the one place the live
// test looks at.
func TestEachFaultBreaksExactlyWhatItNames(t *testing.T) {
	for what, tt := range map[string]struct {
		fault       refca.Fault
		foreign     string
		wildcard    string
		sctProblem  string
		issuedTotal int
	}{
		"clean":                   {0, "caa", "caa", "", 1},
		"I1 ignores accounturi":   {refca.IgnoreAccountURI, "issued", "caa", "", 2},
		"I2 ignores issuewild":    {refca.IgnoreIssuewild, "caa", "issued", "", 2},
		"I3 a bad SCT signature":  {refca.BadSCT, "caa", "caa", "signature", 1},
		"I4 an SCT of one log":    {refca.OneLog, "caa", "caa", "fewer than two", 1},
		"I5 no SCT":               {refca.NoSCT, "caa", "caa", "no SCT", 1},
		"I6 SCTs of another cert": {refca.SCTOfOtherCertificate, "caa", "caa", "signature", 1},
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, tt.fault)
			a, acct := w.account(t)
			b, _ := w.account(t)
			w.permit(acct)
			der, err := w.order(t, a, name, true)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := x509.ParseCertificate(der[0])
			issuer, _ := x509.ParseCertificate(der[1])
			got := strings.Join(ctlog.Check(leaf, issuer, w.ca.LogList()), "; ")
			if (tt.sctProblem == "") != (got == "") || !strings.Contains(got, tt.sctProblem) {
				t.Errorf("SCTs: %q, want %q", got, tt.sctProblem)
			}
			if _, err := w.order(t, b, name, true); problemType(err) != tt.foreign {
				t.Errorf("foreign account: %s, want %s", problemType(err), tt.foreign)
			}
			if _, err := w.order(t, a, "*."+name, true); problemType(err) != tt.wildcard {
				t.Errorf("wildcard: %s, want %s", problemType(err), tt.wildcard)
			}
			if n := len(w.ca.Issued()); n != tt.issuedTotal {
				t.Errorf("%d issued, want %d", n, tt.issuedTotal)
			}
		})
	}
}

func TestAccountsAndRequests(t *testing.T) {
	w := newWorld(t, 0)
	a, _ := w.account(t)
	ctx := context.Background()
	acct, err := a.GetReg(ctx, "")
	if err != nil || acct.Status != acme.StatusValid {
		t.Fatalf("%v %+v", err, acct)
	}
	if err := a.DeactivateReg(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AuthorizeOrder(ctx, acme.DomainIDs(name)); problemType(err) != "unauthorized" {
		t.Errorf("a deactivated account: %s", problemType(err))
	}
	if n := w.ca.Accounts(); n != 1 {
		t.Errorf("%d accounts", n)
	}
	post := func(path, body string) (int, string) {
		resp, err := w.client.Post(w.base+path, "application/jose+json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	for what, body := range map[string]string{
		"no JSON":           `nope`,
		"no protected":      `{"payload":"","signature":""}`,
		"protected garbage": `{"protected":"!!","payload":"","signature":""}`,
		"no nonce":          `{"protected":"` + b64(`{"alg":"ES256","url":"x","jwk":{}}`) + `","payload":"","signature":""}`,
	} {
		if code, body := post("/new-acct", body); code != http.StatusBadRequest || !strings.Contains(body, "urn:ietf:params:acme:error:") {
			t.Errorf("%s: %d %s", what, code, body)
		}
	}
	if code, _ := post("/nowhere", `{}`); code != http.StatusNotFound {
		t.Errorf("an unknown path: %d", code)
	}
	resp, err := w.client.Head(w.base + "/new-nonce")
	if err != nil || resp.Header.Get("Replay-Nonce") == "" {
		t.Errorf("new-nonce: %v", err)
	}
}

func TestRequestsWithDefectsAreRefused(t *testing.T) {
	w := newWorld(t, 0)
	a, acct := w.account(t)
	ctx := context.Background()
	w.permit(acct)
	o, err := a.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		t.Fatal(err)
	}
	z, _ := a.GetAuthorization(ctx, o.AuthzURLs[0])
	rec, _ := a.DNS01ChallengeRecord(z.Challenges[0].Token)
	w.zone.setTXT("_acme-challenge."+name, rec)
	if _, err := a.Accept(ctx, z.Challenges[0]); err != nil {
		t.Fatal(err)
	}
	// A CSR for another name than the order is refused, and the order stays ready.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"other.example"}}, key)
	if _, _, err := a.CreateOrderCert(ctx, o.FinalizeURL, csr, true); problemType(err) != "badCSR" {
		t.Errorf("a CSR for another name: %s", problemType(err))
	}
	if _, _, err := a.CreateOrderCert(ctx, o.FinalizeURL, []byte{1, 2}, true); problemType(err) != "badCSR" {
		t.Errorf("garbage: %s", problemType(err))
	}
	if got, err := a.GetOrder(ctx, o.URI); err != nil || got.Status != acme.StatusReady {
		t.Errorf("order %v %+v", err, got)
	}
	// Another account sees no foreign order, and orders only DNS names.
	b, _ := w.account(t)
	if _, err := b.GetOrder(ctx, o.URI); problemType(err) != "unauthorized" {
		t.Errorf("a foreign order: %s", problemType(err))
	}
	if _, err := b.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "ip", Value: "127.0.0.1"}}); problemType(err) != "rejectedIdentifier" {
		t.Errorf("an IP identifier: %s", problemType(err))
	}
	if _, err := b.AuthorizeOrder(ctx, nil); problemType(err) != "malformed" {
		t.Errorf("no identifier: %s", problemType(err))
	}
	// A finalize before the order is ready.
	o2, err := b.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		t.Fatal(err)
	}
	csr2, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if _, _, err := b.CreateOrderCert(ctx, o2.FinalizeURL, csr2, true); problemType(err) != "orderNotReady" {
		t.Errorf("not ready: %s", problemType(err))
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
