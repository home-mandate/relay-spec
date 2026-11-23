// SPDX-License-Identifier: Apache-2.0

package refca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// crtShTime is the form of the times of crt.sh.
const crtShTime = "2006-01-02T15:04:05"

// listed is a certificate as the search sources show it.
type listed struct {
	id        int
	names     []string
	pubkey    string
	serial    *big.Int
	notBefore time.Time
	notAfter  time.Time
}

func listedOf(c *x509.Certificate, id int) listed {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return listed{id: id, names: c.DNSNames, pubkey: hex.EncodeToString(sum[:]), serial: c.SerialNumber,
		notBefore: c.NotBefore, notAfter: c.NotAfter}
}

// otherKey is the entry of a certificate for the same names with another key and serial.
func otherKey(e listed) listed {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	sum := sha256.Sum256(must(x509.MarshalPKIXPublicKey(&key.PublicKey)))
	e.pubkey = hex.EncodeToString(sum[:])
	e.serial = new(big.Int).Add(e.serial, big.NewInt(1))
	return e
}

// matching returns the listed certificates that hold one of the names.
func (c *CA) matching(names ...string) []listed {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []listed
	for _, e := range c.listed {
		if slices.ContainsFunc(e.names, func(n string) bool { return slices.Contains(names, n) }) {
			out = append(out, e)
		}
	}
	return out
}

// certSpotter answers like /v1/issuances of the Cert Spotter API with match_wildcards: the
// certificates for the domain and for the wildcard that covers it, after the ID "after".
func (c *CA) certSpotter(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	_, parent, _ := strings.Cut(domain, ".")
	after, _ := strconv.Atoi(q.Get("after"))
	out := []map[string]any{}
	for _, e := range c.matching(domain, "*."+parent) {
		if e.id > after {
			out = append(out, map[string]any{"id": strconv.Itoa(e.id), "dns_names": e.names, "pubkey_sha256": e.pubkey,
				"not_before": e.notBefore.UTC().Format(time.RFC3339), "not_after": e.notAfter.UTC().Format(time.RFC3339)})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// crtSh answers like crt.sh with output=json: the certificates for the name in q.
func (c *CA) crtSh(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, e := range c.matching(r.URL.Query().Get("q")) {
		out = append(out, map[string]any{"id": e.id, "name_value": strings.Join(e.names, "\n"), "serial_number": e.serial.Text(16),
			"not_before": e.notBefore.UTC().Format(crtShTime), "not_after": e.notAfter.UTC().Format(crtShTime)})
	}
	writeJSON(w, http.StatusOK, out)
}
