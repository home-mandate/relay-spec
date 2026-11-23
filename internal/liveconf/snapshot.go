// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	// maxSourceBytes limits one answer of a search source.
	maxSourceBytes = 4 << 20
	// maxSourcePages limits the pages of Cert Spotter that the snapshot reads.
	maxSourcePages = 10
	// crtShTime is the form of the times of crt.sh, in UTC.
	crtShTime = "2006-01-02T15:04:05"
)

// errSource is a search source that did not answer with a list.
var errSource = errors.New("the source did not answer with a list")

// verifySnapshot checks through both search sources of ct-sources.md that Certificate
// Transparency shows no certificate for the standard name, or for a wildcard that covers it,
// with another key than the certificate of the run, that is valid at some time since the run
// began (RELAY-v0 section 8.3).
func (r *run) verifySnapshot(ctx context.Context, f ctFile, leaf *x509.Certificate) {
	src := r.env.Sources
	if src.CertSpotter == "" || src.CrtSh == "" {
		r.skip(ClassIssuance)
		r.incomplete("no search sources, so the snapshot of Certificate Transparency was not taken")
		return
	}
	_, parent, _ := strings.Cut(f.Name, ".")
	covers := func(n string) bool {
		n = strings.ToLower(strings.TrimSpace(n))
		return n == f.Name || n == "*."+parent
	}
	spotted, err1 := r.certSpotter(ctx, f.Name, leaf, f.Since, covers)
	listed, err2 := r.crtSh(ctx, []string{f.Name, "*." + parent}, leaf, f.Since, covers)
	var problems []string
	if spotted > 0 {
		problems = append(problems, fmt.Sprintf("Cert Spotter shows %d certificates for the name with another key", spotted))
	}
	if listed > 0 {
		problems = append(problems, fmt.Sprintf("crt.sh shows %d certificates for the name with another serial number", listed))
	}
	switch {
	case len(problems) > 0:
		r.fail(ClassIssuance, CheckIssuanceSnapshot, strings.Join(problems, "; "), titleOf(CheckIssuanceSnapshot))
	case err1 != nil || err2 != nil:
		r.skip(ClassIssuance)
		r.incomplete("a search source did not answer, so the snapshot of Certificate Transparency was not taken; run -ct-verify again")
	default:
		r.pass(ClassIssuance)
	}
}

// getJSON fetches a list from a search source.
func (r *run) getJSON(ctx context.Context, u string, v any) error {
	got, err := r.web.get(ctx, u, maxSourceBytes)
	if err != nil || got.Status != http.StatusOK || got.Over || json.Unmarshal(got.Body, v) != nil {
		return errSource
	}
	return nil
}

// certSpotter counts the certificates for the name with another key than the leaf that are
// valid after since, by the issuances of the Cert Spotter API with match_wildcards.
func (r *run) certSpotter(ctx context.Context, name string, leaf *x509.Certificate, since time.Time, covers func(string) bool) (int, error) {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	own := hex.EncodeToString(sum[:])
	foreign, after := 0, ""
	for range maxSourcePages {
		q := url.Values{"domain": {name}, "include_subdomains": {"false"}, "match_wildcards": {"true"}, "expand": {"dns_names"}}
		if after != "" {
			q.Set("after", after)
		}
		var page []struct {
			ID       string    `json:"id"`
			Names    []string  `json:"dns_names"`
			Pubkey   string    `json:"pubkey_sha256"`
			NotAfter time.Time `json:"not_after"`
		}
		if err := r.getJSON(ctx, strings.TrimSuffix(r.env.Sources.CertSpotter, "/")+"/v1/issuances?"+q.Encode(), &page); err != nil {
			return foreign, err
		}
		if len(page) == 0 {
			return foreign, nil
		}
		for _, e := range page {
			if !strings.EqualFold(e.Pubkey, own) && e.NotAfter.After(since) && slices.ContainsFunc(e.Names, covers) {
				foreign++
			}
		}
		after = page[len(page)-1].ID
	}
	// More pages than the tool reads: the newest certificates were not seen.
	return foreign, errSource
}

// crtSh counts the certificates for the names with another serial number than the leaf that
// are valid after since, by the search of crt.sh for each name.
func (r *run) crtSh(ctx context.Context, names []string, leaf *x509.Certificate, since time.Time, covers func(string) bool) (int, error) {
	foreign := 0
	for _, n := range names {
		var list []struct {
			Names    string `json:"name_value"`
			Serial   string `json:"serial_number"`
			NotAfter string `json:"not_after"`
		}
		if err := r.getJSON(ctx, r.env.Sources.CrtSh+"?"+url.Values{"q": {n}, "output": {"json"}}.Encode(), &list); err != nil {
			return foreign, err
		}
		for _, e := range list {
			serial, ok := new(big.Int).SetString(e.Serial, 16)
			notAfter, err := time.Parse(crtShTime, strings.TrimSuffix(e.NotAfter, "Z"))
			if !ok || err != nil {
				return foreign, errSource
			}
			if serial.Cmp(leaf.SerialNumber) != 0 && notAfter.After(since) && slices.ContainsFunc(strings.Split(e.Names, "\n"), covers) {
				foreign++
			}
		}
	}
	return foreign, nil
}
