// SPDX-License-Identifier: Apache-2.0

package ctlog_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/relay-spec/internal/ctlog"
)

// TestTheSnapshotOfTheGoogleListVerifies: the list of 2026-11-23 in testdata verifies with the
// key the tool holds, and a byte changed in it does not (RS-E4: the snapshot serves offline tests only).
func TestTheSnapshotOfTheGoogleListVerifies(t *testing.T) {
	data := must(os.ReadFile("testdata/log_list.json"))
	sig := must(os.ReadFile("testdata/log_list.sig"))
	if err := ctlog.VerifySignature(data, sig, ctlog.GoogleKey()); err != nil {
		t.Fatalf("the snapshot does not verify: %v", err)
	}
	changed := bytes.Replace(data, []byte(`"Google"`), []byte(`"Goofle"`), 1)
	if err := ctlog.VerifySignature(changed, sig, ctlog.GoogleKey()); err == nil {
		t.Error("a changed list verifies")
	}
	list, err := ctlog.ParseList(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Operators) < 5 {
		t.Fatalf("%d operators", len(list.Operators))
	}
	// A tiled (Static CT) log of the list is found as well as an RFC 6962 log.
	for _, id := range []string{"1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=", "utuIpG+cr6QJDoLlk1bbbni0pT9YLbCBl5UkLym2jJg="} {
		var logID [32]byte
		copy(logID[:], must(base64.StdEncoding.DecodeString(id)))
		if l, op := list.Find(logID); l == nil || op != "Google" {
			t.Errorf("log %s: %v, operator %q", id, l, op)
		}
	}
}

func TestParseListRefusesWhatIsNoList(t *testing.T) {
	for name, data := range map[string]string{
		"no JSON":           `nope`,
		"no operators":      `{"version":"1","log_list_timestamp":"2026-11-23T00:00:00Z","operators":[]}`,
		"two states":        listWith(`"state":{"usable":{"timestamp":"2026-01-01T00:00:00Z"},"retired":{"timestamp":"2026-02-01T00:00:00Z"}}`),
		"no state":          listWith(`"state":{}`),
		"unknown state":     listWith(`"state":{"shiny":{"timestamp":"2026-01-01T00:00:00Z"}}`),
		"trailing data":     `{"operators":[{"name":"A"}]} {}`,
		"duplicate members": `{"operators":[{"name":"A"}],"operators":[{"name":"A"}]}`,
	} {
		if _, err := ctlog.ParseList([]byte(data)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	huge := `{"operators":[{"name":"` + strings.Repeat("x", ctlog.MaxListBytes) + `"}]}`
	if _, err := ctlog.ParseList([]byte(huge)); err == nil {
		t.Error("a list beyond the limit parsed")
	}
}

// listWith is a list with one log of a fresh key and the given state member.
func listWith(state string) string {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	der := must(x509.MarshalPKIXPublicKey(&key.PublicKey))
	id := sha256.Sum256(der)
	return `{"version":"1","log_list_timestamp":"2026-11-23T00:00:00Z","operators":[{"name":"A","logs":[{"description":"a","log_id":"` +
		b64(id[:]) + `","key":"` + b64(der) + `","url":"https://a.example/","mmd":86400,` + state + `}]}]}`
}

func TestLogsWithAWrongIDOrKeyAreLeftOut(t *testing.T) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	der := must(x509.MarshalPKIXPublicKey(&key.PublicKey))
	usable := `"mmd":1,"state":{"usable":{"timestamp":"2026-01-01T00:00:00Z"}}`
	data := `{"version":"1","log_list_timestamp":"2026-11-23T00:00:00Z","operators":[{"name":"A","logs":[` +
		`{"log_id":"` + b64(make([]byte, 32)) + `","key":"` + b64(der) + `",` + usable + `},` +
		`{"log_id":"` + b64(sha256Of([]byte("x"))) + `","key":"` + b64([]byte("x")) + `",` + usable + `}]}]}`
	list, err := ctlog.ParseList([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(list.Operators[0].Logs); n != 0 {
		t.Errorf("%d logs kept", n)
	}
}

// logKey is a test log: its key and its entry in a list.
type logKey struct {
	signer   crypto.Signer
	operator string
	state    string
	since    time.Time
	start    time.Time
	end      time.Time
}

func newLog(operator string) logKey {
	return logKey{signer: must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), operator: operator, state: "usable",
		since: time.Now().Add(-48 * time.Hour), start: time.Now().Add(-365 * 24 * time.Hour), end: time.Now().Add(365 * 24 * time.Hour)}
}

func listOf(t *testing.T, logs ...logKey) *ctlog.List {
	t.Helper()
	byOp := map[string][]map[string]any{}
	var order []string
	for _, l := range logs {
		der := must(x509.MarshalPKIXPublicKey(l.signer.Public()))
		id := sha256.Sum256(der)
		entry := map[string]any{
			"description": l.operator, "log_id": id[:], "key": der, "mmd": 86400, "url": "https://log.example/",
			"state":             map[string]any{l.state: map[string]any{"timestamp": l.since}},
			"temporal_interval": map[string]any{"start_inclusive": l.start, "end_exclusive": l.end},
		}
		if _, ok := byOp[l.operator]; !ok {
			order = append(order, l.operator)
		}
		byOp[l.operator] = append(byOp[l.operator], entry)
	}
	ops := []map[string]any{}
	for _, name := range order {
		ops = append(ops, map[string]any{"name": name, "logs": byOp[name]})
	}
	data := must(json.Marshal(map[string]any{"version": "1", "log_list_timestamp": time.Now(), "operators": ops}))
	list, err := ctlog.ParseList(data)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// chain is a CA and a leaf with the SCTs of the logs embedded as a CA embeds them.
type chain struct{ leaf, issuer *x509.Certificate }

func issue(t *testing.T, tamper func([]ctlog.SCT), logs ...logKey) chain {
	t.Helper()
	caKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ca := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))))
	leafKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: []string{"h.homes.example.org"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(6 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	pre := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey))))
	var scts []ctlog.SCT
	for _, l := range logs {
		scts = append(scts, must(ctlog.SignPrecert(l.signer, pre.RawTBSCertificate, ca.RawSubjectPublicKeyInfo, time.Now())))
	}
	if tamper != nil {
		tamper(scts)
	}
	ext := must(ctlog.MarshalSCTList(scts))
	tmpl.ExtraExtensions = []pkix.Extension{{Id: ctlog.OIDSCTList, Value: ext}}
	leaf := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey))))
	return chain{leaf, ca}
}

func TestPrecertTBSIsTheTBSWithoutTheSCTs(t *testing.T) {
	c := issue(t, nil, newLog("A"))
	tbs, err := ctlog.PrecertTBS(c.leaf)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tbs, c.leaf.RawTBSCertificate) || bytes.Contains(tbs, must(asn1.Marshal(ctlog.OIDSCTList))) {
		t.Error("the SCT extension is still in the TBSCertificate")
	}
	if _, err := ctlog.PrecertTBS(c.issuer); err == nil {
		t.Error("a certificate without SCTs gave a precertificate TBS")
	}
}

func TestCheckJudgesTheSCTsOfACertificate(t *testing.T) {
	a, b, a2 := newLog("A"), newLog("B"), newLog("A")
	unknown := newLog("C")
	retired := newLog("B")
	retired.state, retired.since = "retired", time.Now().Add(-time.Hour)
	readonlyLater := newLog("B")
	readonlyLater.state, readonlyLater.since = "readonly", time.Now().Add(time.Hour)
	pending := newLog("B")
	pending.state = "pending"
	shard := newLog("B")
	shard.end = time.Now().Add(24 * time.Hour)
	list := listOf(t, a, b, a2, retired, readonlyLater, pending, shard)
	for name, tt := range map[string]struct {
		logs    []logKey
		tamper  func([]ctlog.SCT)
		problem string
	}{
		"two operators":              {logs: []logKey{a, b}},
		"a log in read-only later":   {logs: []logKey{a, readonlyLater}},
		"an unknown log is not used": {logs: []logKey{a, b, unknown}},
		"one SCT":                    {logs: []logKey{a}, problem: "fewer than two"},
		"one operator twice":         {logs: []logKey{a, a2}, problem: "fewer than two"},
		"only unknown logs":          {logs: []logKey{unknown}, problem: "fewer than two"},
		"no SCT":                     {problem: "no SCT"},
		"a bad signature":            {logs: []logKey{a, b}, tamper: func(s []ctlog.SCT) { s[1].Signature[10] ^= 1 }, problem: "signature"},
		"a log retired before":       {logs: []logKey{a, retired}, problem: "not usable"},
		"a pending log":              {logs: []logKey{a, pending}, problem: "not usable"},
		"outside the shard":          {logs: []logKey{a, shard}, problem: "temporal interval"},
		"a version other than v1":    {logs: []logKey{a, b}, tamper: func(s []ctlog.SCT) { s[0].Version = 1 }, problem: "version"},
		"a changed timestamp":        {logs: []logKey{a, b}, tamper: func(s []ctlog.SCT) { s[0].Timestamp += 3_600_000 }, problem: "signature"},
	} {
		t.Run(name, func(t *testing.T) {
			var c chain
			if tt.logs == nil {
				c = issue(t, nil, newLog("A"))
				c.leaf = c.issuer
			} else {
				c = issue(t, tt.tamper, tt.logs...)
			}
			got := strings.Join(ctlog.Check(c.leaf, c.issuer, list), "; ")
			if (tt.problem == "") != (got == "") || !strings.Contains(got, tt.problem) {
				t.Errorf("problems %q, want %q", got, tt.problem)
			}
		})
	}
}

func TestParseSCTListRefusesGarbage(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":            {},
		"no octet string":  {0x30, 0},
		"short list":       octets([]byte{0, 5, 0, 3}),
		"empty list":       octets([]byte{0, 0}),
		"short SCT":        octets([]byte{0, 3, 0, 1, 0}),
		"trailing bytes":   append(octets([]byte{0, 0}), 0),
		"trailing in list": octets([]byte{0, 2, 0, 0, 1}),
	} {
		if _, err := ctlog.ParseSCTList(data); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestSignPrecertWithRSAAndAnEmptyList(t *testing.T) {
	rsaKey := must(rsa.GenerateKey(rand.Reader, 2048))
	sct, err := ctlog.SignPrecert(rsaKey, []byte{1}, []byte{2}, time.Now())
	if err != nil || sct.SigAlg != 1 {
		t.Errorf("RSA: %v, algorithm %d", err, sct.SigAlg)
	}
	if _, err := ctlog.MarshalSCTList(nil); err == nil {
		t.Error("an empty list was marshalled")
	}
}

func FuzzSCTList(f *testing.F) {
	a := newLog("A")
	sct := must(ctlog.SignPrecert(a.signer, []byte{0x30, 0x03, 0x02, 0x01, 0x01}, []byte{1}, time.Now()))
	f.Add(must(ctlog.MarshalSCTList([]ctlog.SCT{sct, sct})))
	f.Add([]byte{0x04, 0x02, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		scts, err := ctlog.ParseSCTList(data)
		if err != nil {
			return
		}
		again, err := ctlog.MarshalSCTList(scts)
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("a parsed list does not marshal to the same bytes: %v", err)
		}
	})
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func octets(b []byte) []byte { return must(asn1.Marshal(b)) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sha256Of(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// TestKeysOfTheLogs: SCTs of an RSA log verify; logs with Ed25519 or P-384 keys are left out of
// the list, and a log key of such a type cannot sign.
func TestKeysOfTheLogs(t *testing.T) {
	a := newLog("A")
	rsaLog := newLog("B")
	rsaLog.signer = must(rsa.GenerateKey(rand.Reader, 2048))
	rsaLog.operator = "B\x01" + strings.Repeat("b", 80)
	list := listOf(t, a, rsaLog)
	if p := ctlog.Check(issue(t, nil, a, rsaLog).leaf, issue(t, nil, a).issuer, list); len(p) == 0 {
		t.Error("SCTs of another issuer verified")
	}
	c := issue(t, nil, a, rsaLog)
	if p := ctlog.Check(c.leaf, c.issuer, list); len(p) != 0 {
		t.Errorf("an RSA log: %v", p)
	}
	bad := issue(t, func(s []ctlog.SCT) { s[1].Signature[0] ^= 1 }, a, rsaLog)
	p := strings.Join(ctlog.Check(bad.leaf, bad.issuer, list), "; ")
	if !strings.Contains(p, "signature") || strings.ContainsRune(p, 1) || len(p) > 400 {
		t.Errorf("a bad RSA signature: %q", p)
	}
	wrongHash := issue(t, func(s []ctlog.SCT) { s[0].HashAlg = 2 }, a, rsaLog)
	if p := ctlog.Check(wrongHash.leaf, wrongHash.issuer, list); len(p) == 0 {
		t.Error("an SCT with SHA-1 verified")
	}
	_, edKey := must2(ed25519.GenerateKey(rand.Reader))
	if _, err := ctlog.SignPrecert(edKey, []byte{1}, []byte{2}, time.Now()); err == nil {
		t.Error("an Ed25519 log key signed")
	}
	p384 := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	for name, key := range map[string]crypto.PublicKey{"Ed25519": edKey.Public(), "P-384": &p384.PublicKey} {
		der := must(x509.MarshalPKIXPublicKey(key))
		data := `{"operators":[{"name":"A","tiled_logs":[{"log_id":"` + b64(sha256Of(der)) + `","key":"` + b64(der) +
			`","mmd":60,"state":{"usable":{"timestamp":"2026-01-01T00:00:00Z"}}}]}]}`
		l, err := ctlog.ParseList([]byte(data))
		if err != nil || len(l.Operators[0].TiledLogs) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ctlog.ParseList([]byte(`{"operators":[{"name":"A","tiled_logs":[{"state":{}}]}]}`)); err == nil {
		t.Error("a tiled log without a state parsed")
	}
	if ctlog.GoogleKey().N.BitLen() != 4096 {
		t.Error("the key of the log list is not RSA 4096")
	}
}

func TestPrecertTBSRefusesBrokenCertificates(t *testing.T) {
	c := issue(t, nil, newLog("A"))
	for name, tbs := range map[string][]byte{
		"no sequence":           {0x04, 0x00},
		"a broken element":      {0x30, 0x02, 0x02, 0x05},
		"broken extensions":     {0x30, 0x04, 0xa3, 0x02, 0x04, 0x00},
		"a broken extension":    {0x30, 0x06, 0xa3, 0x04, 0x30, 0x02, 0x02, 0x00},
		"an extension sans OID": {0x30, 0x08, 0xa3, 0x06, 0x30, 0x04, 0x30, 0x02, 0x02, 0x00},
	} {
		broken := *c.leaf
		broken.RawTBSCertificate = tbs
		if _, err := ctlog.PrecertTBS(&broken); err == nil {
			t.Errorf("%s: no error", name)
		}
		if p := ctlog.Check(&broken, c.issuer, listOf(t, newLog("A"))); len(p) == 0 {
			t.Errorf("%s: Check passed", name)
		}
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}
