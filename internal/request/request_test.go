// SPDX-License-Identifier: Apache-2.0

package request

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/home-mandate/relay-spec/internal/enroll"
	"github.com/home-mandate/spec/jws"
)

// The key of RFC 8037 appendix A.1 and the values of the requests below.
const (
	rfc8037Seed   = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037Public = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	testNonce     = "oFvnlFP1wIhRlYS2jTaXbA"
	testPair      = "https://relay-operator.example/enroll/pair"
	testKeyURL    = "https://relay-operator.example/enroll/key-change"
	testInstall   = "https://relay-operator.example/enroll/installation/k7q2xwmpd4hj3n6rt5vbyc2ezu"
	testCertURL   = testInstall + "/certificate"
	testPayload   = `{"code":"ABCD-EFGH-IJKL-MNOP"}`
	testKCChange  = `{"installation":"` + testInstall + `","old_key":{"kty":"OKP","crv":"Ed25519","x":"` + rfc8037Public + `"}}`
	// maxErrorBytes bounds an error message, whatever the input.
	maxErrorBytes = 512
)

var b64 = base64.RawURLEncoding

// ed25519Order is L, the order of the Ed25519 base point.
var ed25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

func rfcKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	seed, err := b64.DecodeString(rfc8037Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func ecKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jwkOf(t testing.TB, key crypto.PublicKey) string {
	t.Helper()
	data, err := jws.MarshalJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// rawSign signs a header given as JSON text with the gateway's signer (internal/enroll), so
// that the tests can build any header and a second implementation signs what this one reads.
func rawSign(t testing.TB, head, payload string, key crypto.PrivateKey) string {
	t.Helper()
	signer, err := enroll.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := b64.EncodeToString([]byte(head))
	sig := signer.Sign(jws.SigningInput(encoded, []byte(payload)))
	return encoded + "." + b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(sig)
}

func pairHeader(alg, jwk string) string {
	return `{"alg":"` + alg + `","nonce":"` + testNonce + `","url":"` + testPair + `","jwk":` + jwk + `}`
}

func kidHeader(alg, rawURL string) string {
	return `{"alg":"` + alg + `","nonce":"` + testNonce + `","url":"` + rawURL + `","kid":"` + testInstall + `"}`
}

func TestVerifyRequests(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	for name, tt := range map[string]struct {
		compact string
		key     crypto.PublicKey
		jwk     crypto.PublicKey
		kid     string
		url     string
		payload string
	}{
		"pairing Ed25519": {rawSign(t, pairHeader("EdDSA", jwkOf(t, ed.Public())), testPayload, ed), nil, ed.Public(), "", testPair, testPayload},
		"pairing ES256":   {rawSign(t, pairHeader("ES256", jwkOf(t, ec.Public())), testPayload, ec), ec.Public(), ec.Public(), "", testPair, testPayload},
		"jwk with space":  {rawSign(t, pairHeader("EdDSA", strings.Replace(jwkOf(t, ed.Public()), ",", ",\n"+strings.Repeat(" ", 2048), 1)), testPayload, ed), nil, ed.Public(), "", testPair, testPayload},
		"kid Ed25519":     {rawSign(t, kidHeader("EdDSA", testCertURL), testPayload, ed), ed.Public(), nil, testInstall, testCertURL, testPayload},
		"kid ES256":       {rawSign(t, kidHeader("ES256", testCertURL), `{}`, ec), ec.Public(), nil, testInstall, testCertURL, `{}`},
		"POST-as-GET":     {rawSign(t, kidHeader("EdDSA", testInstall), "", ed), ed.Public(), nil, testInstall, testInstall, ""},
	} {
		h, payload, err := Verify(tt.compact, tt.key)
		if err != nil || string(payload) != tt.payload || h.Nonce != testNonce || h.URL != tt.url || h.Kid != tt.kid {
			t.Errorf("%s: Verify = %+v, %q, %v", name, h, payload, err)
		}
		if (h.JWK == nil) != (tt.jwk == nil) || (h.JWK != nil && !sameKey(h.JWK, tt.jwk)) {
			t.Errorf("%s: jwk = %v", name, h.JWK)
		}
		parsed, _, err := Parse(tt.compact)
		if err != nil || parsed.Alg != h.Alg {
			t.Errorf("%s: Parse = %+v, %v", name, parsed, err)
		}
	}
}

// The requests that the gateway's request builder writes read back here, and each of its
// deliberate defects is malformed.
func TestRequestsOfTheGatewayBuilder(t *testing.T) {
	for _, alg := range []string{enroll.AlgEdDSA, enroll.AlgES256} {
		s, err := enroll.Generate(alg)
		if err != nil {
			t.Fatal(err)
		}
		good := enroll.Spec{Signer: s, JWK: true, Nonce: testNonce, URL: testPair, Payload: testPayload}
		if h, _, err := Verify(good.Compact(), nil); err != nil || !sameKey(h.JWK, s.Public()) {
			t.Errorf("%s pairing: %+v, %v", alg, h, err)
		}
		for defect := enroll.ExtraHeaderMember; defect <= enroll.PaddedPayload; defect++ {
			if defect == enroll.HighS && alg != enroll.AlgES256 {
				continue
			}
			bad := good
			bad.Defect = defect
			if _, _, err := Verify(bad.Compact(), nil); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s defect %d: %v, want ErrMalformed", alg, defect, err)
			}
		}
	}
}

func TestVerifyRequestDistinguishesMalformedFromBadSignature(t *testing.T) {
	ed, other, ec := rfcKey(t), ed25519.NewKeyFromSeed(make([]byte, 32)), ecKey(t)
	edJWK, ecJWK := jwkOf(t, ed.Public()), jwkOf(t, ec.Public())
	pair := func(members string) string {
		return `{"alg":"EdDSA","nonce":"` + testNonce + `","url":"` + testPair + `"` + members + `}`
	}
	kid := func(members string) string {
		return `{"alg":"EdDSA","nonce":"` + testNonce + `","url":"` + testCertURL + `","kid":"` + testInstall + `"` + members + `}`
	}
	good := rawSign(t, kid(""), testPayload, ed)
	parts := strings.Split(good, ".")
	for name, tt := range map[string]struct {
		compact string
		key     crypto.PublicKey
		want    error
		reason  string // a part of the message that names the defect
	}{
		"signed by another key":      {rawSign(t, kid(""), testPayload, other), ed.Public(), ErrSignature, "signature does not verify"},
		"payload changed":            {parts[0] + "." + b64.EncodeToString([]byte(`{"code":"X"}`)) + "." + parts[2], ed.Public(), ErrSignature, "signature does not verify"},
		"pairing signed by another":  {rawSign(t, pair(`,"jwk":`+edJWK), testPayload, other), nil, ErrSignature, "signature does not verify"},
		"kid without key":            {good, nil, ErrKey, "<nil>"},
		"key other than jwk":         {rawSign(t, pair(`,"jwk":`+edJWK), testPayload, ed), other.Public(), ErrKey, "key is not the jwk"},
		"nil P-256 key for jwk":      {rawSign(t, pair(`,"jwk":`+edJWK), testPayload, ed), (*ecdsa.PublicKey)(nil), ErrKey, "key is not the jwk"},
		"unsupported key":            {good, "key", ErrKey, "string"},
		"ES256 for an Ed25519 key":   {rawSign(t, strings.Replace(kid(""), "EdDSA", "ES256", 1), testPayload, ec), ed.Public(), ErrMalformed, "algorithm ES256 for a EdDSA key"},
		"EdDSA for a P-256 key":      {good, ec.Public(), ErrMalformed, "algorithm EdDSA for a ES256 key"},
		"ES256 with an OKP jwk":      {rawSign(t, strings.Replace(pair(`,"jwk":`+edJWK), "EdDSA", "ES256", 1), testPayload, ec), nil, ErrMalformed, "algorithm ES256 for a EdDSA key"},
		"EdDSA with an EC jwk":       {rawSign(t, pair(`,"jwk":`+ecJWK), testPayload, ed), nil, ErrMalformed, "algorithm EdDSA for a ES256 key"},
		"both jwk and kid":           {rawSign(t, kid(`,"jwk":`+edJWK), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"neither jwk nor kid":        {rawSign(t, pair(""), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"crit":                       {rawSign(t, kid(`,"crit":["b64"]`), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"b64":                        {rawSign(t, kid(`,"b64":false`), testPayload, ed), ed.Public(), ErrMalformed, "one of jwk and kid"},
		"duplicate member":           {rawSign(t, kid(`,"kid":"`+testInstall+`"`), testPayload, ed), ed.Public(), ErrMalformed, `header: malformed JSON: duplicate key "kid"`},
		"upper-case member":          {rawSign(t, strings.Replace(kid(""), `"url"`, `"URL"`, 1), testPayload, ed), ed.Public(), ErrMalformed, "url must be a string"},
		"jwk with d":                 {rawSign(t, pair(`,"jwk":`+strings.Replace(edJWK, `}`, `,"d":"`+rfc8037Seed+`"}`, 1)), testPayload, ed), nil, ErrMalformed, "members other than"},
		"jwk with kid":               {rawSign(t, pair(`,"jwk":`+strings.Replace(edJWK, `}`, `,"kid":"k"}`, 1)), testPayload, ed), nil, ErrMalformed, "members other than"},
		"jwk not an object":          {rawSign(t, pair(`,"jwk":"`+rfc8037Public+`"`), testPayload, ed), nil, ErrMalformed, "jwk: not a JSON object"},
		"jwk without kty":            {rawSign(t, pair(`,"jwk":{"crv":"Ed25519","x":"`+rfc8037Public+`","y":"x"}`), testPayload, ed), nil, ErrMalformed, "kty must be a string"},
		"jwk crv null":               {rawSign(t, pair(`,"jwk":{"kty":"OKP","crv":null,"x":"`+rfc8037Public+`"}`), testPayload, ed), nil, ErrMalformed, "crv must be a string"},
		"jwk short x":                {rawSign(t, pair(`,"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQAB"}`), testPayload, ed), nil, ErrMalformed, "x is not 32 bytes"},
		"jwk RSA":                    {rawSign(t, pair(`,"jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}`), testPayload, ed), nil, ErrMalformed, "crv must be a string"},
		"jwk EC without y":           {rawSign(t, strings.Replace(pair(`,"jwk":{"kty":"EC","crv":"P-256","x":"`+rfc8037Public+`"}`), "EdDSA", "ES256", 1), testPayload, ec), nil, ErrMalformed, "members other than"},
		"jwk P-256 off the curve":    {rawSign(t, strings.Replace(pair(`,"jwk":`+offCurve(t, ecJWK)), "EdDSA", "ES256", 1), testPayload, ec), nil, ErrMalformed, "not on curve"},
		"jwk small order":            {rawSign(t, pair(`,"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), testPayload, ed), nil, ErrMalformed, "small order"},
		"alg none":                   {rawSign(t, strings.Replace(kid(""), "EdDSA", "none", 1), testPayload, ed), ed.Public(), ErrMalformed, `algorithm "none"`},
		"alg null":                   {rawSign(t, strings.Replace(kid(""), `"EdDSA"`, "null", 1), testPayload, ed), ed.Public(), ErrMalformed, "alg must be a string"},
		"nonce too short":            {rawSign(t, strings.Replace(kid(""), testNonce, testNonce[:21], 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce not base64url":        {rawSign(t, strings.Replace(kid(""), testNonce, strings.Repeat("+", 22), 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce not canonical":        {rawSign(t, strings.Replace(kid(""), testNonce, testNonce[:21]+"B", 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce too long":             {rawSign(t, strings.Replace(kid(""), testNonce, strings.Repeat("A", 132), 1), testPayload, ed), ed.Public(), ErrMalformed, "is not base64url of at least 16 bytes"},
		"nonce of 128 characters":    {rawSign(t, strings.Replace(kid(""), testNonce, strings.Repeat("A", 128), 1), testPayload, other), ed.Public(), ErrSignature, "signature does not verify"},
		"nonce a number":             {rawSign(t, strings.Replace(kid(""), `"`+testNonce+`"`, "1", 1), testPayload, ed), ed.Public(), ErrMalformed, "nonce must be a string"},
		"url over http":              {rawSign(t, strings.Replace(kid(""), `"url":"https`, `"url":"http`, 1), testPayload, ed), ed.Public(), ErrMalformed, `url "http://`},
		"url too long":               {rawSign(t, strings.Replace(kid(""), testCertURL, urlOf(maxURLChars+1), 1), testPayload, ed), ed.Public(), ErrMalformed, `url "https://`},
		"url of the longest length":  {rawSign(t, strings.Replace(kid(""), testCertURL, urlOf(maxURLChars), 1), testPayload, other), ed.Public(), ErrSignature, "signature does not verify"},
		"kid with query":             {rawSign(t, strings.Replace(kid(""), testInstall+`"`, testInstall+`?a"`, 1), testPayload, ed), ed.Public(), ErrMalformed, `kid "https://`},
		"header an array":            {rawSign(t, `[]`, testPayload, ed), ed.Public(), ErrMalformed, "header is not a JSON object"},
		"header null":                {rawSign(t, `null`, testPayload, ed), ed.Public(), ErrMalformed, "header is not a JSON object"},
		"header duplicate in I-JSON": {rawSign(t, kid(`,"alg":"EdDSA"`), testPayload, ed), ed.Public(), ErrMalformed, `header: malformed JSON: duplicate key "alg"`},
		"payload not an object":      {rawSign(t, kid(""), `[1]`, ed), ed.Public(), ErrMalformed, "payload is not a JSON object"},
		"payload null":               {rawSign(t, kid(""), `null`, ed), ed.Public(), ErrMalformed, "payload is not a JSON object"},
		"payload duplicate member":   {rawSign(t, kid(""), `{"a":1,"a":2}`, ed), ed.Public(), ErrMalformed, `payload: malformed JSON: duplicate key "a"`},
		"payload padded":             {parts[0] + "." + parts[1] + "=." + parts[2], ed.Public(), ErrMalformed, "payload: illegal base64"},
		"header with line feed":      {parts[0][:4] + "\n" + parts[0][4:] + "." + parts[1] + "." + parts[2], ed.Public(), ErrMalformed, "header: not canonical base64url"},
		"signature not base64url":    {parts[0] + "." + parts[1] + ".!!", ed.Public(), ErrMalformed, "signature: illegal base64"},
		"signature short":            {parts[0] + "." + parts[1] + "." + parts[2][:40], ed.Public(), ErrMalformed, "signature of 30 bytes"},
		"signature empty":            {parts[0] + "." + parts[1] + ".", ed.Public(), ErrMalformed, "signature of 0 bytes"},
		"two segments":               {parts[0] + "." + parts[1], ed.Public(), ErrMalformed, "not a compact JWS"},
		"four segments":              {good + ".", ed.Public(), ErrMalformed, "not a compact JWS"},
		"too long":                   {parts[0] + "." + strings.Repeat("A", jws.MaxCompactBytes) + "." + parts[2], ed.Public(), ErrMalformed, "not a compact JWS"},
	} {
		_, _, err := Verify(tt.compact, tt.key)
		if !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: err = %v, want %v with %q", name, err, tt.want, tt.reason)
		}
		onlyKind(t, name, err, tt.want)
	}
}

// onlyKind: an error is exactly one of the errors of this package and none of the core's jws.
func onlyKind(t *testing.T, name string, err, want error) {
	t.Helper()
	for _, other := range []error{ErrMalformed, ErrSignature, ErrKey, jws.ErrMalformed, jws.ErrSignature, jws.ErrKey} {
		if other != want && errors.Is(err, other) {
			t.Errorf("%s: err = %v is also %v", name, err, other)
		}
	}
}

// TestSignatureSpellingIsMalformed: a signature that breaks the spelling rules is malformed
// before it is checked (RELAY-v0 section 5.1 step 1), even if a lenient library would accept
// it. Each fixture verifies before it is changed.
func TestSignatureSpellingIsMalformed(t *testing.T) {
	ed, ec := rfcKey(t), ecKey(t)
	compact := rawSign(t, kidHeader("ES256", testCertURL), testPayload, ec)
	if _, _, err := Verify(compact, ec.Public()); err != nil {
		t.Fatalf("ES256 fixture: %v", err)
	}
	parts := strings.Split(compact, ".")
	sig, _ := b64.DecodeString(parts[2])
	n := elliptic.P256().Params().N
	high := append(sig[:32:32], new(big.Int).Sub(n, new(big.Int).SetBytes(sig[32:])).FillBytes(make([]byte, 32))...)
	if _, _, err := Verify(parts[0]+"."+parts[1]+"."+b64.EncodeToString(high), ec.Public()); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "higher s") {
		t.Errorf("high s: %v, want ErrMalformed for the higher s", err)
	}

	edCompact := rawSign(t, kidHeader("EdDSA", testCertURL), testPayload, ed)
	if _, _, err := Verify(edCompact, ed.Public()); err != nil {
		t.Fatalf("EdDSA fixture: %v", err)
	}
	parts = strings.Split(edCompact, ".")
	sig, _ = b64.DecodeString(parts[2])
	// S + L verifies in libraries that reduce S.
	s := make([]byte, 32)
	for i, b := range sig[32:] {
		s[31-i] = b
	}
	sum := new(big.Int).Add(new(big.Int).SetBytes(s), ed25519Order).FillBytes(make([]byte, 32))
	large := append([]byte{}, sig[:32]...)
	for i := range sum {
		large = append(large, sum[31-i])
	}
	if _, _, err := Verify(parts[0]+"."+parts[1]+"."+b64.EncodeToString(large), ed.Public()); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "EdDSA signature not canonical") {
		t.Errorf("S >= L: %v, want ErrMalformed for a non-canonical signature", err)
	}
	// R with y = p + 1, not canonical.
	badR := append([]byte{0xee}, append(bytesOf(0xff, 30), 0x7f)...)
	if _, _, err := Verify(parts[0]+"."+parts[1]+"."+b64.EncodeToString(append(badR, sig[32:]...)), ed.Public()); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "EdDSA signature not canonical") {
		t.Errorf("non-canonical R: %v, want ErrMalformed for a non-canonical signature", err)
	}
}

// offCurve returns a P-256 jwk whose y is changed in its lowest bit, so that the point is
// not on the curve.
func offCurve(t testing.TB, ecJWK string) string {
	t.Helper()
	var k struct{ X, Y string }
	if err := json.Unmarshal([]byte(ecJWK), &k); err != nil {
		t.Fatal(err)
	}
	y, err := b64.DecodeString(k.Y)
	if err != nil {
		t.Fatal(err)
	}
	y[len(y)-1] ^= 1
	return `{"kty":"EC","crv":"P-256","x":"` + k.X + `","y":"` + b64.EncodeToString(y) + `"}`
}

// TestRequestErrorsQuoteOnlyAPrefix: an error quotes at most maxQuotedBytes of a value that
// the sender chose.
func TestRequestErrorsQuoteOnlyAPrefix(t *testing.T) {
	ed := rfcKey(t)
	long := strings.Repeat("A", maxNonceChars+4)
	kid := kidHeader("EdDSA", testCertURL)
	for name, head := range map[string]string{
		"nonce": strings.Replace(kid, testNonce, long, 1),
		"url":   strings.Replace(kid, testCertURL, "http://"+long, 1),
		"kid":   strings.Replace(kid, `"kid":"`+testInstall, `"kid":"https://`+strings.ToLower(long)+"/", 1),
		"alg":   strings.Replace(kid, "EdDSA", long, 1),
	} {
		_, _, err := Verify(rawSign(t, head, testPayload, ed), ed.Public())
		if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "...") {
			t.Errorf("%s: err = %v, want ErrMalformed naming %s with a cut value", name, err, name)
		}
		if strings.Contains(err.Error(), long[:maxQuotedBytes+1]) || strings.Contains(err.Error(), strings.ToLower(long[:maxQuotedBytes+1])) {
			t.Errorf("%s: err quotes more than %d bytes: %v", name, maxQuotedBytes, err)
		}
	}
	for s, want := range map[string]string{
		"short":                               `"short"`,
		strings.Repeat("a", maxQuotedBytes):   `"` + strings.Repeat("a", maxQuotedBytes) + `"`,
		strings.Repeat("a", maxQuotedBytes+1): `"` + strings.Repeat("a", maxQuotedBytes) + `"...`,
	} {
		if got := quote(s); got != want {
			t.Errorf("quote(%d bytes) = %s, want %s", len(s), got, want)
		}
	}
}

// urlOf returns an HTTPS URL of the schema with exactly n characters.
func urlOf(n int) string {
	return testCertURL + "/" + strings.Repeat("a", n-len(testCertURL)-1)
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func keyChangeHeader(alg, jwk string) string {
	return `{"alg":"` + alg + `","jwk":` + jwk + `,"url":"` + testKeyURL + `"}`
}

func TestKeyChange(t *testing.T) {
	newKey, oldKey, ec := ed25519.NewKeyFromSeed(bytesOf(7, 32)), rfcKey(t), ecKey(t)
	for name, key := range map[string]crypto.Signer{"Ed25519": newKey, "P-256": ec} {
		signer, err := enroll.NewSigner(key)
		if err != nil {
			t.Fatal(err)
		}
		compact := enroll.KeyChangeJWS(signer, jwkOf(t, oldKey.Public()), testInstall, testKeyURL)
		h, payload, err := VerifyKeyChange(compact)
		if err != nil || h.URL != testKeyURL || !sameKey(h.JWK, key.Public()) || !strings.Contains(string(payload), testInstall) {
			t.Errorf("%s: VerifyKeyChange = %+v, %q, %v", name, h, payload, err)
		}
		if _, _, err := ParseKeyChange(compact); err != nil {
			t.Errorf("%s: ParseKeyChange: %v", name, err)
		}
	}
	newJWK := jwkOf(t, newKey.Public())
	head := keyChangeHeader("EdDSA", newJWK)
	good := rawSign(t, head, testKCChange, newKey)
	parts := strings.Split(good, ".")
	for name, tt := range map[string]struct {
		compact string
		want    error
		reason  string
	}{
		"signed by the old key": {rawSign(t, head, testKCChange, oldKey), ErrSignature, "signature does not verify"},
		"with nonce":            {rawSign(t, strings.Replace(head, `{`, `{"nonce":"`+testNonce+`",`, 1), testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"with kid":              {rawSign(t, strings.Replace(head, `{`, `{"kid":"`+testInstall+`",`, 1), testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"without jwk":           {rawSign(t, `{"alg":"EdDSA","kid":"`+testInstall+`","url":"`+testKeyURL+`"}`, testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"without url":           {rawSign(t, `{"alg":"EdDSA","jwk":`+newJWK+`}`, testKCChange, newKey), ErrMalformed, "exactly alg, jwk and url"},
		"bad url":               {rawSign(t, strings.Replace(head, "https", "http", 1), testKCChange, newKey), ErrMalformed, `url "http://`},
		"alg ES256":             {rawSign(t, strings.Replace(head, "EdDSA", "ES256", 1), testKCChange, ec), ErrMalformed, "algorithm ES256 for a EdDSA key"},
		"alg missing":           {rawSign(t, `{"jwk":`+newJWK+`,"url":"`+testKeyURL+`","x":1}`, testKCChange, newKey), ErrMalformed, "alg must be a string"},
		"header not base64url":  {"!!." + parts[1] + "." + parts[2], ErrMalformed, "header: illegal base64"},
		"empty payload":         {rawSign(t, head, "", newKey), ErrMalformed, "no payload"},
		"payload array":         {rawSign(t, head, "[]", newKey), ErrMalformed, "payload is not a JSON object"},
		"padded signature":      {good + "=", ErrMalformed, "signature: illegal base64"},
		"two segments":          {parts[0] + "." + parts[1], ErrMalformed, "not a compact JWS"},
		"too long":              {parts[0] + "." + strings.Repeat("A", MaxKeyChangeBytes) + "." + parts[2], ErrMalformed, "larger than"},
	} {
		_, _, err := VerifyKeyChange(tt.compact)
		if !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: err = %v, want %v with %q", name, err, tt.want, tt.reason)
		}
		onlyKind(t, name, err, tt.want)
	}
}

// The bound of a key change is inclusive: one of exactly MaxKeyChangeBytes is read, one byte
// more is malformed.
func TestKeyChangeAtItsBound(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytesOf(7, 32))
	jwk := jwkOf(t, key.Public())
	// A byte of payload adds one or two characters of base64url, a character of the url one
	// or two; together they reach every length.
	build := func(pad, extra int) string {
		head := `{"alg":"EdDSA","jwk":` + jwk + `,"url":"` + testKeyURL + strings.Repeat("a", extra) + `"}`
		return rawSign(t, head, `{"installation":"`+testInstall+`","pad":"`+strings.Repeat("x", pad)+`"}`, key)
	}
	// Three bytes of payload are four characters: start a few bytes below the bound.
	start := (MaxKeyChangeBytes-len(build(0, 0)))*3/4 - 4
	var exact, over string
	for pad := start; exact == "" || over == ""; pad++ {
		for extra := range 3 {
			switch n := len(build(pad, extra)); {
			case n == MaxKeyChangeBytes && exact == "":
				exact = build(pad, extra)
			case n == MaxKeyChangeBytes+1 && over == "":
				over = build(pad, extra)
			}
		}
		if pad > start+8 {
			t.Fatal("no key change of the exact length")
		}
	}
	if _, _, err := VerifyKeyChange(exact); err != nil {
		t.Errorf("a key change of %d bytes: %v", len(exact), err)
	}
	if _, _, err := VerifyKeyChange(over); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a key change of %d bytes: %v, want ErrMalformed", len(over), err)
	}
}

// FuzzVerifyRequest: arbitrary input never panics, errors are exactly one of the three kinds
// and of bounded length, and nothing verifies but the requests that were signed. Parse accepts
// what Verify accepts.
func FuzzVerifyRequest(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pair := rawSign(f, pairHeader("EdDSA", jwkOf(f, key.Public())), `{"code":"ABCD"}`, key)
	read := rawSign(f, kidHeader("EdDSA", testInstall), "", key)
	change := rawSign(f, keyChangeHeader("EdDSA", jwkOf(f, key.Public())), `{"installation":"`+testInstall+`"}`, key)
	for _, seed := range []string{pair, read, change, "", "..", "a.b.c", pair + "A", read[:len(read)-2]} {
		f.Add(seed)
	}
	oneOf := func(t *testing.T, err error) {
		if len(err.Error()) > maxErrorBytes {
			t.Fatalf("error of %d bytes: %.200s", len(err.Error()), err)
		}
		kinds := 0
		for _, kind := range []error{ErrMalformed, ErrSignature, ErrKey} {
			if errors.Is(err, kind) {
				kinds++
			}
		}
		if kinds != 1 {
			t.Fatalf("error %v is of %d kinds", err, kinds)
		}
	}
	f.Fuzz(func(t *testing.T, input string) {
		h, _, err := Verify(input, key.Public())
		if err == nil {
			if input != pair && input != read {
				t.Fatalf("Verify accepted %q", input)
			}
			if (h.JWK == nil) == (h.Kid == "") {
				t.Fatalf("header %+v has not exactly one of jwk and kid", h)
			}
			if _, _, err := Parse(input); err != nil {
				t.Fatalf("Parse refused what Verify accepted: %v", err)
			}
		} else {
			oneOf(t, err)
		}
		if _, _, err := VerifyKeyChange(input); err == nil && input != change {
			t.Fatalf("VerifyKeyChange accepted %q", input)
		} else if err != nil {
			oneOf(t, err)
		}
	})
}
