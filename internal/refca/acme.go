// SPDX-License-Identifier: Apache-2.0

package refca

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/home-mandate/relay-spec/internal/ctlog"
)

const (
	orderLifetime = time.Hour
	serialShift   = 32
)

// Accounts (RFC 8555 section 7.3).

func (c *CA) newAccount(w http.ResponseWriter, req *request) {
	var p struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting"`
	}
	_ = json.Unmarshal(req.payload, &p)
	tp := thumbprint(req.jwk)
	c.mu.Lock()
	var acct *account
	for _, a := range c.accounts {
		if a.thumbprint == tp {
			acct = a
		}
	}
	created := acct == nil && !p.OnlyReturnExisting
	if created {
		acct = &account{id: randomHex(idBytes), key: req.jwk, thumbprint: tp, status: "valid"}
		c.accounts[acct.id] = acct
	}
	c.mu.Unlock()
	if acct == nil {
		writeProblem(w, &problem{http.StatusBadRequest, "accountDoesNotExist", "no account with this key"})
		return
	}
	w.Header().Set("Location", c.AccountPrefix()+acct.id)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, c.accountDoc(acct))
}

func (c *CA) account(w http.ResponseWriter, req *request) {
	if req.id != req.acct.id {
		writeProblem(w, &problem{http.StatusUnauthorized, "unauthorized", "another account"})
		return
	}
	var p struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(req.payload, &p)
	if p.Status == "deactivated" {
		c.mu.Lock()
		req.acct.status = "deactivated"
		c.mu.Unlock()
	}
	w.Header().Set("Location", c.AccountPrefix()+req.acct.id)
	writeJSON(w, http.StatusOK, c.accountDoc(req.acct))
}

func (c *CA) accountDoc(a *account) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"status": a.status, "orders": c.url("/orders/" + a.id)}
}

// Orders and authorizations (RFC 8555 sections 7.4 and 7.5).

func (c *CA) newOrder(w http.ResponseWriter, req *request) {
	var p struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}
	if json.Unmarshal(req.payload, &p) != nil || len(p.Identifiers) == 0 {
		writeProblem(w, malformed("an order names at least one identifier"))
		return
	}
	for _, ident := range p.Identifiers {
		if ident.Type != "dns" || ident.Value == "" {
			writeProblem(w, &problem{http.StatusBadRequest, "rejectedIdentifier", "only DNS names"})
			return
		}
	}
	o := &order{id: randomHex(idBytes), account: req.acct.id, status: "pending", expires: time.Now().Add(orderLifetime)}
	c.mu.Lock()
	for _, ident := range p.Identifiers {
		value := strings.ToLower(ident.Value)
		base, wild := strings.CutPrefix(value, "*.")
		z := &authz{id: randomHex(idBytes), account: req.acct.id, name: base, wildcard: wild, token: randomToken(), status: "pending"}
		c.authzs[z.id] = z
		o.identifiers = append(o.identifiers, value)
		o.authzs = append(o.authzs, z.id)
	}
	c.orders[o.id] = o
	doc := c.orderDoc(o)
	c.mu.Unlock()
	w.Header().Set("Location", c.url("/order/"+o.id))
	writeJSON(w, http.StatusCreated, doc)
}

func randomToken() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// orderDoc is the order as a client sees it; the lock is held.
func (c *CA) orderDoc(o *order) map[string]any {
	ids := []map[string]string{}
	urls := []string{}
	for i, v := range o.identifiers {
		ids = append(ids, map[string]string{"type": "dns", "value": v})
		urls = append(urls, c.url("/authz/"+o.authzs[i]))
	}
	doc := map[string]any{"status": c.orderStatus(o), "expires": o.expires.UTC().Format(time.RFC3339),
		"identifiers": ids, "authorizations": urls, "finalize": c.url("/finalize/" + o.id)}
	if o.cert != "" {
		doc["certificate"] = c.url("/cert/" + o.cert)
	}
	return doc
}

// orderStatus follows the authorizations of a pending order; the lock is held.
func (c *CA) orderStatus(o *order) string {
	if o.status != "pending" {
		return o.status
	}
	ready := true
	for _, id := range o.authzs {
		switch c.authzs[id].status {
		case "invalid":
			o.status = "invalid"
			return o.status
		case "pending":
			ready = false
		}
	}
	if ready {
		o.status = "ready"
	}
	return o.status
}

// ownOrder returns the order of the request's account, or nil; the lock is held.
func (c *CA) ownOrder(req *request) *order {
	o := c.orders[req.id]
	if o == nil || o.account != req.acct.id {
		return nil
	}
	return o
}

// ownAuthz returns the authorization of the request's account, or nil; the lock is held.
func (c *CA) ownAuthz(req *request) *authz {
	z := c.authzs[req.id]
	if z == nil || z.account != req.acct.id {
		return nil
	}
	return z
}

var notOwned = &problem{http.StatusUnauthorized, "unauthorized", "no such resource of this account"}

func (c *CA) getOrder(w http.ResponseWriter, req *request) {
	c.mu.Lock()
	o := c.ownOrder(req)
	var doc map[string]any
	if o != nil {
		doc = c.orderDoc(o)
	}
	c.mu.Unlock()
	if o == nil {
		writeProblem(w, notOwned)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (c *CA) getAuthz(w http.ResponseWriter, req *request) {
	c.mu.Lock()
	z := c.ownAuthz(req)
	var doc map[string]any
	if z != nil {
		doc = map[string]any{"identifier": map[string]string{"type": "dns", "value": z.name}, "status": z.status,
			"expires": time.Now().Add(orderLifetime).UTC().Format(time.RFC3339), "wildcard": z.wildcard,
			"challenges": []map[string]any{c.challengeDoc(z)}}
	}
	c.mu.Unlock()
	if z == nil {
		writeProblem(w, notOwned)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

// challengeDoc is the one challenge of an authorization; the lock is held.
func (c *CA) challengeDoc(z *authz) map[string]any {
	doc := map[string]any{"type": "dns-01", "url": c.url("/chall/" + z.id), "token": z.token, "status": z.status}
	if z.problem != nil {
		doc["error"] = z.problem.document()
	}
	return doc
}

// challenge validates DNS-01 at once (RFC 8555 section 8.4), then checks the CAA records as
// a CA does after a successful validation.
func (c *CA) challenge(w http.ResponseWriter, req *request) {
	c.mu.Lock()
	z := c.ownAuthz(req)
	pending := z != nil && z.status == "pending"
	c.mu.Unlock()
	if z == nil {
		writeProblem(w, notOwned)
		return
	}
	if pending {
		p := c.validate(z, req.acct)
		c.mu.Lock()
		z.status, z.problem = "valid", p
		if p != nil {
			z.status = "invalid"
		}
		c.mu.Unlock()
	}
	c.mu.Lock()
	doc := c.challengeDoc(z)
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, doc)
}

func (c *CA) validate(z *authz, acct *account) *problem {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	sum := sha256.Sum256([]byte(z.token + "." + acct.thumbprint))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	values, err := c.lookupTXT(ctx, "_acme-challenge."+z.name)
	if err != nil {
		return &problem{http.StatusBadRequest, "dns", "the TXT records cannot be looked up"}
	}
	if !slices.Contains(values, want) {
		return &problem{http.StatusForbidden, "unauthorized", "no TXT record with the key authorization"}
	}
	ok, err := c.permits(ctx, z.name, z.wildcard, c.AccountPrefix()+acct.id)
	if err != nil {
		return &problem{http.StatusBadRequest, "dns", "the CAA records cannot be looked up"}
	}
	if !ok {
		return &problem{http.StatusForbidden, "caa", "the CAA records forbid issuance"}
	}
	return nil
}

// lookupTXT returns the TXT records of the name, from what the CA keeps if it keeps them.
func (c *CA) lookupTXT(ctx context.Context, name string) ([]string, error) {
	now := time.Now()
	c.mu.Lock()
	kept, ok := c.txt[name]
	c.mu.Unlock()
	if ok && now.Before(kept.until) {
		return kept.values, nil
	}
	values, err := c.cfg.DNS.TXT(ctx, name)
	if err != nil || c.cfg.TXTCache <= 0 {
		return values, err
	}
	c.mu.Lock()
	c.txt[name] = keptTXT{values: values, until: now.Add(c.cfg.TXTCache)}
	c.mu.Unlock()
	return values, nil
}

// Certificates (RFC 8555 section 7.4).

func (c *CA) finalize(w http.ResponseWriter, req *request) {
	c.mu.Lock()
	o := c.ownOrder(req)
	status := ""
	var names []string
	if o != nil {
		status, names = c.orderStatus(o), slices.Clone(o.identifiers)
	}
	c.mu.Unlock()
	switch {
	case o == nil:
		writeProblem(w, notOwned)
		return
	case status != "ready":
		writeProblem(w, &problem{http.StatusForbidden, "orderNotReady", "the order is " + status})
		return
	}
	csr := parseCSR(req.payload)
	if csr == nil || !sameNames(csr.DNSNames, names) {
		writeProblem(w, &problem{http.StatusBadRequest, "badCSR", "the CSR does not ask for the names of the order"})
		return
	}
	chain := c.issue(csr)
	certID := randomHex(idBytes)
	c.mu.Lock()
	c.certs[certID] = chain
	o.cert, o.status = certID, "valid"
	doc := c.orderDoc(o)
	c.mu.Unlock()
	w.Header().Set("Location", c.url("/order/"+o.id))
	writeJSON(w, http.StatusOK, doc)
}

func parseCSR(payload []byte) *x509.CertificateRequest {
	var p struct {
		CSR string `json:"csr"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	der, err := base64.RawURLEncoding.DecodeString(p.CSR)
	if err != nil {
		return nil
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil
	}
	return csr
}

func sameNames(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// issue signs a certificate for the CSR with the SCTs of the logs embedded, as the faults say.
func (c *CA) issue(csr *x509.CertificateRequest) [][]byte {
	c.mu.Lock()
	c.serial.Add(c.serial, big.NewInt(1))
	serial := new(big.Int).Lsh(c.serial, serialShift)
	c.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: serial, DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(certLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !c.cfg.Faults.Has(NoSCT) {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: ctlog.OIDSCTList, Value: c.scts(tmpl, csr)}}
	}
	der := must(x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key))
	cert := must(x509.ParseCertificate(der))
	c.mu.Lock()
	c.issued = append(c.issued, cert)
	c.listed = append(c.listed, listedOf(cert, len(c.listed)+1))
	if c.cfg.Faults.Has(ExtraCertificate) {
		c.listed = append(c.listed, otherKey(listedOf(cert, len(c.listed)+1)))
	}
	c.mu.Unlock()
	return [][]byte{der, c.cert.Raw}
}

// scts returns the extension value with the SCTs of the logs for the certificate tmpl will
// give: the logs sign its TBSCertificate without the extension, which is what a precertificate
// without its poison has.
func (c *CA) scts(tmpl *x509.Certificate, csr *x509.CertificateRequest) []byte {
	f := c.cfg.Faults
	signed := *tmpl
	if f.Has(SCTOfOtherCertificate) {
		signed.SerialNumber = new(big.Int).Add(tmpl.SerialNumber, big.NewInt(1))
	}
	pre := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, &signed, c.cert, csr.PublicKey, c.key))))
	logs := c.logs
	if f.Has(OneLog) {
		logs = logs[:1]
	}
	var list []ctlog.SCT
	for _, l := range logs {
		list = append(list, must(l.Submit(pre.RawTBSCertificate, c.cert.RawSubjectPublicKeyInfo, time.Now())))
	}
	if f.Has(BadSCT) {
		last := list[len(list)-1].Signature
		last[len(last)-1] ^= 1
	}
	return must(ctlog.MarshalSCTList(list))
}

func (c *CA) getCert(w http.ResponseWriter, req *request) {
	c.mu.Lock()
	chain, ok := c.certs[req.id]
	c.mu.Unlock()
	if !ok {
		writeProblem(w, &problem{http.StatusNotFound, "malformed", "no such certificate"})
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	for _, der := range chain {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
}
