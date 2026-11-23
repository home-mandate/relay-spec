// SPDX-License-Identifier: Apache-2.0

// Package refca is a reference CA for the tests of the class issuance of relay-conformance
// (RELAY-v0 section 8.3), and for them only: a subset of ACME (RFC 8555) with DNS-01 as the only
// challenge, the CAA rules of RFC 8659 with the parameters accounturi and validationmethods of
// RFC 8657, and two stub Certificate Transparency logs whose SCTs it embeds. Each deliberate
// defect, switched on by a Fault, breaks exactly what one check of the class looks at. Neither
// the tool nor the files of package relay import it (a test checks that).
package refca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/dnsq"
	"github.com/home-mandate/relay-spec/internal/reflog"
)

// Identity is the issuer domain name of the reference CA, its caa_identity.
const Identity = "ca.example.com"

// Host is the host of its ACME server.
const Host = "acme." + Identity

// Fault switches on one deliberate defect of the CA. Faults combine as a mask.
type Fault uint16

// Defects of the CA, each breaking what one check of the class issuance looks at.
const (
	// IgnoreAccountURI (I1) issues to an account that the parameter accounturi does not name.
	IgnoreAccountURI Fault = 1 << iota
	// IgnoreIssuewild (I2) decides on a wildcard name by the issue properties alone.
	IgnoreIssuewild
	// BadSCT (I3) embeds an SCT whose signature does not verify.
	BadSCT
	// OneLog (I4) embeds the SCT of one log only.
	OneLog
	// NoSCT (I5) embeds no SCT.
	NoSCT
	// SCTOfOtherCertificate (I6) embeds SCTs that the logs gave for another certificate.
	SCTOfOtherCertificate
	// NotIncluded (I7) has its first log leave out the entries it gives SCTs for.
	NotIncluded
	// BadTreeHead (I8) has its first log sign its tree heads wrongly.
	BadTreeHead
	// ExtraCertificate (I9) issues, for every name it issues for, a second certificate with
	// another key, which only the search sources show.
	ExtraCertificate
)

// Has reports whether f contains the defect.
func (f Fault) Has(defect Fault) bool { return f&defect != 0 }

// Resolver is the CA's view of DNS: the TXT and the CAA records of a name. A name without
// records has an empty answer and no error.
type Resolver interface {
	TXT(ctx context.Context, name string) ([]string, error)
	CAA(ctx context.Context, name string) ([]dnsq.CAA, error)
}

// Config configures a reference CA.
type Config struct {
	// DNS is how the CA looks up records.
	DNS Resolver
	// Faults are the defects of the CA.
	Faults Fault
}

const (
	certLifetime = 6 * 24 * time.Hour
	caLifetime   = 30 * 24 * time.Hour
	maxBodyBytes = 64 << 10
	nonceBytes   = 16
	idBytes      = 8
	tokenBytes   = 32
	dnsTimeout   = 5 * time.Second
)

// CA is a reference CA.
type CA struct {
	cfg    Config
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	logs   []*reflog.Log
	list   *ctlog.List
	serial *big.Int

	mu       sync.Mutex
	nonces   map[string]bool
	accounts map[string]*account
	orders   map[string]*order
	authzs   map[string]*authz
	certs    map[string][][]byte
	issued   []*x509.Certificate
	// listed are the certificates the search sources show.
	listed []listed
}

type account struct {
	id         string
	key        *ecdsa.PublicKey
	thumbprint string
	status     string
}

type order struct {
	id          string
	account     string
	identifiers []string
	authzs      []string
	status      string
	cert        string
	expires     time.Time
}

type authz struct {
	id       string
	account  string
	name     string
	wildcard bool
	token    string
	status   string
	problem  *problem
}

// New returns a reference CA with a CA certificate and two logs made for this call.
func New(cfg Config) *CA {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "refca test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(caLifetime),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	cert := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key))))
	c := &CA{cfg: cfg, key: key, cert: cert, serial: big.NewInt(1),
		nonces: map[string]bool{}, accounts: map[string]*account{}, orders: map[string]*order{},
		authzs: map[string]*authz{}, certs: map[string][][]byte{}}
	// Log A follows RFC 6962, log B is tiled; both include at once (a maximum merge delay of 0).
	a := reflog.New(c.url("/logs/a/"), false)
	a.SetInclude(!cfg.Faults.Has(NotIncluded))
	a.SetBadTreeHead(cfg.Faults.Has(BadTreeHead))
	c.logs = []*reflog.Log{a, reflog.New(c.url("/logs/b/"), true)}
	c.list = must(reflog.List(c.logs...))
	return c
}

// Directory returns the URL of the ACME directory.
func (c *CA) Directory() string { return c.url("/directory") }

// AccountPrefix returns the form of an account URI without its number.
func (c *CA) AccountPrefix() string { return c.url("/acct/") }

// Certificate returns the CA certificate that signs the certificates of the CA.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// LogList returns a log list with the two logs of the CA.
func (c *CA) LogList() *ctlog.List { return c.list }

// Issued returns the certificates the CA issued.
func (c *CA) Issued() []*x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*x509.Certificate{}, c.issued...)
}

// Accounts returns the number of accounts.
func (c *CA) Accounts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.accounts)
}

// ActiveAccounts returns the number of accounts that are not deactivated.
func (c *CA) ActiveAccounts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, a := range c.accounts {
		if a.status == "valid" {
			n++
		}
	}
	return n
}

// Handler serves ACME.
func (c *CA) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory", c.directory)
	mux.HandleFunc("HEAD /new-nonce", c.newNonce)
	mux.HandleFunc("GET /new-nonce", c.newNonce)
	mux.HandleFunc("POST /", c.post)
	mux.Handle("GET /logs/a/", c.logs[0].Handler())
	mux.Handle("GET /logs/b/", c.logs[1].Handler())
	mux.HandleFunc("GET /certspotter/v1/issuances", c.certSpotter)
	mux.HandleFunc("GET /crtsh/", c.crtSh)
	return mux
}

// CertSpotter returns the base URL of the search source in the form of the Cert Spotter API.
func (c *CA) CertSpotter() string { return c.url("/certspotter") }

// CrtSh returns the URL of the search source in the form of crt.sh.
func (c *CA) CrtSh() string { return c.url("/crtsh/") }

func (c *CA) url(path string) string { return "https://" + Host + path }

func (c *CA) directory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce": c.url("/new-nonce"), "newAccount": c.url("/new-acct"), "newOrder": c.url("/new-order"),
		"revokeCert": c.url("/revoke-cert"), "keyChange": c.url("/key-change"),
		"meta": map[string]any{"caaIdentities": []string{Identity}},
	})
}

func (c *CA) newNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", c.nonce())
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *CA) nonce() string {
	n := randomHex(nonceBytes)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonces[n] = true
	return n
}

// useNonce consumes a nonce; false if it was not issued or is used up.
func (c *CA) useNonce(n string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.nonces[n] {
		return false
	}
	delete(c.nonces, n)
	return true
}

// routes are the resources a POST reaches; those with an ID end in "/".
var routes = map[string]bool{"new-acct": false, "new-order": false, "acct": true, "order": true,
	"authz": true, "chall": true, "finalize": true, "cert": true}

// post verifies the request and routes it by its path.
func (c *CA) post(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", c.nonce())
	route, id, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	withID, ok := routes[route]
	if !ok || withID != (id != "") || strings.Contains(id, "/") {
		writeProblem(w, &problem{http.StatusNotFound, "malformed", "no such resource"})
		return
	}
	req, p := c.verify(r, route == "new-acct")
	if p != nil {
		writeProblem(w, p)
		return
	}
	req.id = id
	handlers := map[string]func(http.ResponseWriter, *request){
		"new-acct": c.newAccount, "acct": c.account, "new-order": c.newOrder, "order": c.getOrder,
		"authz": c.getAuthz, "chall": c.challenge, "finalize": c.finalize, "cert": c.getCert,
	}
	handlers[route](w, req)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// problem is an ACME error (RFC 8555 section 6.7).
type problem struct {
	status int
	kind   string
	detail string
}

func (p *problem) document() map[string]any {
	return map[string]any{"type": "urn:ietf:params:acme:error:" + p.kind, "detail": p.detail, "status": p.status}
}

func writeProblem(w http.ResponseWriter, p *problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.status)
	_ = json.NewEncoder(w).Encode(p.document())
}

func must[T any](v T, err error) T {
	if err != nil {
		panic("refca: " + err.Error())
	}
	return v
}
