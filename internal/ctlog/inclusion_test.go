// SPDX-License-Identifier: Apache-2.0

package ctlog_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/reflog"
)

// fetcher serves the requests of CheckInclusion from the handlers of reference logs.
func fetcher(logs ...*reflog.Log) ctlog.Fetcher {
	return func(_ context.Context, url string, limit int64) (int, []byte, error) {
		for _, l := range logs {
			if strings.HasPrefix(url, l.Prefix()) {
				rec := httptest.NewRecorder()
				l.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
				body := rec.Body.Bytes()
				if int64(len(body)) > limit {
					return 0, nil, errors.New("too large")
				}
				return rec.Code, body, nil
			}
		}
		return 0, nil, errors.New("no such host")
	}
}

// logged issues a certificate whose SCTs come from the logs, and returns it and its issuer.
func logged(t *testing.T, logs ...*reflog.Log) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	ca := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))))
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), DNSNames: []string{"h.homes.example.org"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour)}
	pre := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey))))
	var scts []ctlog.SCT
	for _, l := range logs {
		scts = append(scts, must(l.Submit(pre.RawTBSCertificate, ca.RawSubjectPublicKeyInfo, time.Now())))
	}
	tmpl.ExtraExtensions = []pkix.Extension{{Id: ctlog.OIDSCTList, Value: must(ctlog.MarshalSCTList(scts))}}
	return must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)))), ca
}

// listFor is a log list with the logs, each of its own operator.
func listFor(t *testing.T, logs ...*reflog.Log) *ctlog.List {
	t.Helper()
	list, err := reflog.List(logs...)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestInclusionInBothKindsOfLogs(t *testing.T) {
	a := reflog.New("https://ct.example.com/a/", false)
	b := reflog.New("https://ct.example.com/b/", true)
	// Entries before ours, so that the proofs and tiles have some depth.
	for range 300 {
		logged(t, a, b)
	}
	leaf, issuer := logged(t, a, b)
	logged(t, a, b)
	list := listFor(t, a, b)
	scts := must(ctlog.SCTsOf(leaf))
	for i, s := range scts {
		lg, _ := list.Find(s.LogID)
		got, err := ctlog.CheckInclusion(context.Background(), fetcher(a, b), lg, s, leaf, issuer)
		if err != nil || !got.Included || got.TreeTime.IsZero() {
			t.Errorf("SCT %d: %+v, %v", i, got, err)
		}
	}
	if idx, ok := ctlog.LeafIndex(scts[1]); !ok || idx != 300 {
		t.Errorf("leaf index of the tiled log: %d %v", idx, ok)
	}
	if _, ok := ctlog.LeafIndex(scts[0]); ok {
		t.Error("an RFC 6962 SCT has a leaf index")
	}
}

func TestInclusionFailures(t *testing.T) {
	for name, tt := range map[string]struct {
		tiled   bool
		change  func(*reflog.Log)
		wantErr error
	}{
		"RFC 6962, not included":          {false, func(l *reflog.Log) { l.SetInclude(false) }, nil},
		"tiled, not included":             {true, func(l *reflog.Log) { l.SetInclude(false) }, nil},
		"RFC 6962, bad tree head":         {false, func(l *reflog.Log) { l.SetBadTreeHead(true) }, ctlog.ErrBadTreeHead},
		"tiled, bad checkpoint":           {true, func(l *reflog.Log) { l.SetBadTreeHead(true) }, ctlog.ErrBadTreeHead},
		"RFC 6962, a proof that is wrong": {false, func(l *reflog.Log) { l.SetBadProof(true) }, ctlog.ErrBadLog},
		"tiled, tiles that do not match":  {true, func(l *reflog.Log) { l.SetBadProof(true) }, ctlog.ErrBadLog},
		"RFC 6962, an empty tree":         {false, func(l *reflog.Log) { l.SetInclude(false); l.Reset() }, nil},
		"tiled, an index beyond the tree": {true, func(l *reflog.Log) { l.SetInclude(false); l.Reset() }, nil},
	} {
		t.Run(name, func(t *testing.T) {
			l := reflog.New("https://ct.example.com/x/", tt.tiled)
			for range 3 {
				logged(t, l)
			}
			tt.change(l)
			leaf, issuer := logged(t, l)
			list := listFor(t, l)
			s := must(ctlog.SCTsOf(leaf))[0]
			lg, _ := list.Find(s.LogID)
			got, err := ctlog.CheckInclusion(context.Background(), fetcher(l), lg, s, leaf, issuer)
			if !errors.Is(err, tt.wantErr) || got.Included {
				t.Errorf("%+v, %v; want %v", got, err, tt.wantErr)
			}
			if tt.wantErr == nil && (err != nil || got.TreeTime.IsZero()) {
				t.Errorf("no time of the tree head: %v", err)
			}
		})
	}
	t.Run("unreachable", func(t *testing.T) {
		l := reflog.New("https://ct.example.com/y/", false)
		leaf, issuer := logged(t, l)
		s := must(ctlog.SCTsOf(leaf))[0]
		lg, _ := listFor(t, l).Find(s.LogID)
		if _, err := ctlog.CheckInclusion(context.Background(), fetcher(), lg, s, leaf, issuer); err == nil || errors.Is(err, ctlog.ErrBadLog) {
			t.Errorf("%v", err)
		}
	})
}

func TestLeafIndexNeedsExactlyItsExtension(t *testing.T) {
	for name, ext := range map[string][]byte{
		"none":       nil,
		"short":      {0, 0, 4, 0, 0, 0, 1},
		"other type": {1, 0, 5, 0, 0, 0, 0, 1},
		"trailing":   {0, 0, 5, 0, 0, 0, 0, 1, 9},
	} {
		if _, ok := ctlog.LeafIndex(ctlog.SCT{Extensions: ext}); ok {
			t.Errorf("%s: an index", name)
		}
	}
	if idx, ok := ctlog.LeafIndex(ctlog.SCT{Extensions: []byte{0, 0, 5, 1, 0, 0, 0, 2}}); !ok || idx != 1<<32+2 {
		t.Errorf("%d %v", idx, ok)
	}
}

// TestAPartialTileThatIsGoneIsTakenFromTheFullTile: a log that grew no longer serves the partial
// tile of an older tree; the hashes come from the full tile.
func TestAPartialTileThatIsGoneIsTakenFromTheFullTile(t *testing.T) {
	l := reflog.New("https://ct.example.com/p/", true)
	for range 5 {
		logged(t, l)
	}
	leaf, issuer := logged(t, l)
	l.SetDropPartialTiles(true)
	s := must(ctlog.SCTsOf(leaf))[0]
	lg, _ := listFor(t, l).Find(s.LogID)
	got, err := ctlog.CheckInclusion(context.Background(), fetcher(l), lg, s, leaf, issuer)
	if err != nil || !got.Included {
		t.Errorf("%+v, %v", got, err)
	}
}

// tamper serves the log, but answers the requests whose URL contains part with status and body.
func tamper(l *reflog.Log, part string, status int, body string) ctlog.Fetcher {
	inner := fetcher(l)
	return func(ctx context.Context, url string, limit int64) (int, []byte, error) {
		if strings.Contains(url, part) {
			return status, []byte(body), nil
		}
		return inner(ctx, url, limit)
	}
}

// TestAnswersOfALogThatDecideNothingOrFail: what a log answers that is no answer, no tree head
// of its own, or a proof that does not verify.
func TestAnswersOfALogThatDecideNothingOrFail(t *testing.T) {
	const (
		noAnswer = "no answer"
		badHead  = "bad tree head"
		badProof = "bad proof"
	)
	origin := "ct.example.com/t"
	for name, tt := range map[string]struct {
		tiled  bool
		part   string
		status int
		body   string
		want   string
	}{
		"sth 500":                 {false, "get-sth", 500, "", noAnswer},
		"sth garbage":             {false, "get-sth", 200, "nope", noAnswer},
		"proof 500":               {false, "get-proof", 500, "", noAnswer},
		"proof 400":               {false, "get-proof", 400, "", noAnswer},
		"proof garbage":           {false, "get-proof", 200, "nope", badProof},
		"proof hash short":        {false, "get-proof", 200, `{"leaf_index":0,"audit_path":["AAAA"]}`, badProof},
		"proof index outside":     {false, "get-proof", 200, `{"leaf_index":99,"audit_path":[]}`, badProof},
		"checkpoint 500":          {true, "checkpoint", 500, "", noAnswer},
		"checkpoint other origin": {true, "checkpoint", 200, "other.example\n1\nAAAA\n\n", badHead},
		"checkpoint no size":      {true, "checkpoint", 200, origin + "\nx\nAAAA\n\n", badHead},
		"checkpoint no signature": {true, "checkpoint", 200, origin + "\n1\n" + strings.Repeat("A", 43) + "=\n\n— other.example AAAA\n", badHead},
		"tile 500":                {true, "tile/", 500, "", noAnswer},
	} {
		t.Run(name, func(t *testing.T) {
			prefix := "https://ct.example.com/t/"
			l := reflog.New(prefix, tt.tiled)
			leaf, issuer := logged(t, l)
			logged(t, l)
			s := must(ctlog.SCTsOf(leaf))[0]
			lg, _ := listFor(t, l).Find(s.LogID)
			_, err := ctlog.CheckInclusion(context.Background(), tamper(l, tt.part, tt.status, tt.body), lg, s, leaf, issuer)
			got := noAnswer
			switch {
			case err == nil:
				got = "no error"
			case errors.Is(err, ctlog.ErrBadTreeHead):
				got = badHead
			case errors.Is(err, ctlog.ErrBadLog):
				got = badProof
			}
			if got != tt.want {
				t.Errorf("%s (%v), want %s", got, err, tt.want)
			}
		})
	}
	t.Run("a tiled SCT without its index", func(t *testing.T) {
		l := reflog.New("https://ct.example.com/u/", true)
		leaf, issuer := logged(t, l)
		s := must(ctlog.SCTsOf(leaf))[0]
		lg, _ := listFor(t, l).Find(s.LogID)
		s.Extensions = nil
		if _, err := ctlog.CheckInclusion(context.Background(), fetcher(l), lg, s, leaf, issuer); !errors.Is(err, ctlog.ErrBadLog) {
			t.Errorf("%v", err)
		}
		if _, err := ctlog.CheckInclusion(context.Background(), fetcher(l), lg, s, issuer, issuer); err == nil {
			t.Error("a certificate without SCTs")
		}
	})
}
