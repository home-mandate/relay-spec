// SPDX-License-Identifier: Apache-2.0

// Package request reads and verifies the requests of RELAY-v0: the JWS that a gateway sends
// to the enrollment endpoint of an operator (section 5.1) and the inner JWS of a key change
// (section 5.5). Unlike a signed mandate, a request names its key by the installation URL
// (kid) or carries it (jwk), so the header is read before the key is known. The header rules
// are this specification's; compact form, signature checks and JWK come from the core's jws
// package.
//
// ErrMalformed stands for the error malformed of section 5.1, ErrSignature for bad-signature.
// ErrKey means that the caller gave no usable key.
package request

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/home-mandate/spec/ijson"
	"github.com/home-mandate/spec/jws"
)

// The errors of a request; every error of this package is exactly one of them.
var (
	ErrMalformed = errors.New("request: malformed")
	ErrSignature = errors.New("request: signature does not verify")
	ErrKey       = errors.New("request: unsupported or unknown key")
)

// Header is the protected header of a request (RELAY-v0 section 5.1): exactly alg, nonce,
// url and one of jwk and kid.
type Header struct {
	Alg   string
	Nonce string
	URL   string
	// JWK is the public key of a pairing request: ed25519.PublicKey or *ecdsa.PublicKey on
	// P-256. It is nil when Kid is set.
	JWK crypto.PublicKey
	// Kid is the installation URL; empty when JWK is set.
	Kid string
}

// KeyChangeHeader is the protected header of the inner JWS of a key change (RELAY-v0
// section 5.5): exactly alg, jwk (the new key) and url, no nonce.
type KeyChangeHeader struct {
	Alg string
	JWK crypto.PublicKey
	URL string
}

const (
	// minNonceBytes: a nonce has at least 128 random bits (RELAY-v0 section 5.1).
	minNonceBytes = 16
	// maxNonceChars and maxURLChars are the bounds of the enrollment schema.
	maxNonceChars = 128
	maxURLChars   = 2048
	// MaxKeyChangeBytes is the bound of $defs/compact_jws of the enrollment schema.
	MaxKeyChangeBytes = 16 << 10
	// signatureBytes is the length of an EdDSA and of an ES256 signature.
	signatureBytes = 64
	// maxQuotedBytes bounds how much of a value from a request an error message quotes.
	maxQuotedBytes = 64
)

// httpsURL is $defs/https_url of the metadata schema: a lower-case DNS host, an optional
// port, a path of unreserved characters, no user info, query, fragment or percent-encoding.
var httpsURL = regexp.MustCompile(`^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]([a-z0-9-]{0,61}[a-z0-9])?(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~/-]*)?$`)

// signed is what verifying a parsed JWS needs.
type signed struct {
	alg   string
	input []byte
	sig   []byte
}

// Parse checks everything about a request that needs no key: the compact form, the header
// profile and the spelling rules of all three segments (RELAY-v0 section 5.1 step 1). It does
// not verify the signature, so that an operator can look up the installation that kid names
// first; Verify does both.
func Parse(compact string) (Header, []byte, error) {
	h, payload, _, err := parse(compact)
	return h, payload, err
}

// Verify checks a request like Parse and verifies its signature with key: the installation
// key that kid names, or, for a header with jwk, nil (or that same key).
func Verify(compact string, key crypto.PublicKey) (Header, []byte, error) {
	h, payload, s, err := parse(compact)
	if err != nil {
		return Header{}, nil, err
	}
	verifier := key
	switch {
	case h.JWK != nil && key == nil:
		verifier = h.JWK
	case h.JWK != nil && !sameKey(key, h.JWK):
		return Header{}, nil, fmt.Errorf("%w: key is not the jwk of the header", ErrKey)
	}
	if err := verifySigned(s, verifier); err != nil {
		return Header{}, nil, err
	}
	return h, payload, nil
}

// ParseKeyChange checks the inner JWS of a key change without verifying its signature: the
// compact form with a payload, the header profile and the spelling rules.
func ParseKeyChange(compact string) (KeyChangeHeader, []byte, error) {
	h, payload, _, err := parseKeyChange(compact)
	return h, payload, err
}

// VerifyKeyChange checks the inner JWS of a key change like ParseKeyChange and verifies its
// signature with the new key, the jwk of its header. Whether url, installation and old_key
// fit the outer request is for the caller (RELAY-v0 section 5.5).
func VerifyKeyChange(compact string) (KeyChangeHeader, []byte, error) {
	h, payload, s, err := parseKeyChange(compact)
	if err != nil {
		return KeyChangeHeader{}, nil, err
	}
	if err := verifySigned(s, h.JWK); err != nil {
		return KeyChangeHeader{}, nil, err
	}
	return h, payload, nil
}

func parse(compact string) (Header, []byte, signed, error) {
	head, body, sig, err := split(compact)
	if err != nil {
		return Header{}, nil, signed{}, err
	}
	h, err := parseHeader(head)
	if err != nil {
		return Header{}, nil, signed{}, err
	}
	payload, s, err := readSigned(h.Alg, head, body, sig, true)
	if err != nil {
		return Header{}, nil, signed{}, err
	}
	return h, payload, s, nil
}

func parseKeyChange(compact string) (KeyChangeHeader, []byte, signed, error) {
	if len(compact) > MaxKeyChangeBytes {
		return KeyChangeHeader{}, nil, signed{}, fmt.Errorf("%w: key change larger than %d bytes", ErrMalformed, MaxKeyChangeBytes)
	}
	head, body, sig, err := split(compact)
	if err != nil {
		return KeyChangeHeader{}, nil, signed{}, err
	}
	h, err := parseKeyChangeHeader(head)
	if err != nil {
		return KeyChangeHeader{}, nil, signed{}, err
	}
	payload, s, err := readSigned(h.Alg, head, body, sig, false)
	if err != nil {
		return KeyChangeHeader{}, nil, signed{}, err
	}
	return h, payload, s, nil
}

// split splits the compact form; jws checks the length before it splits.
func split(compact string) (head, body, sig string, err error) {
	head, body, sig, err = jws.SplitCompact(compact)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: not a compact JWS", ErrMalformed)
	}
	return head, body, sig, nil
}

// decode decodes a segment in its one spelling; part names it in the error.
func decode(part, segment string) ([]byte, error) {
	decoded, err := jws.DecodeSegment(segment)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %s", ErrMalformed, part, reason(err, jws.ErrMalformed))
	}
	return decoded, nil
}

// reason is the message of a jws error without the prefix of its sentinel, so that an error
// of this package wraps only its own sentinels.
func reason(err, sentinel error) string {
	return strings.TrimPrefix(err.Error(), sentinel.Error()+": ")
}

// readSigned decodes payload and signature and checks their spelling.
func readSigned(alg, head, body, sig string, emptyPayload bool) ([]byte, signed, error) {
	if body == "" && !emptyPayload {
		return nil, signed{}, fmt.Errorf("%w: no payload", ErrMalformed)
	}
	payload, err := decode("payload", body)
	if err != nil {
		return nil, signed{}, err
	}
	if err := checkPayload(payload, emptyPayload); err != nil {
		return nil, signed{}, err
	}
	raw, err := decode("signature", sig)
	if err != nil {
		return nil, signed{}, err
	}
	if err := checkSignatureForm(alg, raw); err != nil {
		return nil, signed{}, err
	}
	return payload, signed{alg: alg, input: jws.SigningInput(head, payload), sig: raw}, nil
}

// checkSignatureForm checks the spelling of a signature (SPEC-v0 section 7.1, applied by
// RELAY-v0 section 5.1): 64 octets, for EdDSA a canonical R and S below L, for ES256 the
// lower s. A signature that breaks it is malformed, not bad-signature.
func checkSignatureForm(alg string, sig []byte) error {
	if len(sig) != signatureBytes {
		return fmt.Errorf("%w: signature of %d bytes", ErrMalformed, len(sig))
	}
	if jws.CanonicalSignature(alg, sig) {
		return nil
	}
	if alg == jws.AlgEdDSA {
		return fmt.Errorf("%w: EdDSA signature not canonical", ErrMalformed)
	}
	return fmt.Errorf("%w: ES256 signature with the higher s", ErrMalformed)
}

// verifySigned verifies with key, whose type alg has to match (RELAY-v0 section 5.1).
func verifySigned(s signed, key crypto.PublicKey) error {
	alg, ok := jws.KeyAlgorithm(key)
	if !ok {
		return fmt.Errorf("%w: %T", ErrKey, key)
	}
	if alg != s.alg {
		return fmt.Errorf("%w: algorithm %s for a %s key", ErrMalformed, s.alg, alg)
	}
	if !jws.VerifySignature(s.alg, key, s.input, s.sig) {
		return ErrSignature
	}
	return nil
}

func parseHeader(segment string) (Header, error) {
	var h Header
	members, err := readMembers(segment)
	if err != nil {
		return h, err
	}
	_, hasJWK := members["jwk"]
	_, hasKid := members["kid"]
	if len(members) != 4 || hasJWK == hasKid {
		return h, fmt.Errorf("%w: header must have exactly alg, nonce, url and one of jwk and kid", ErrMalformed)
	}
	if h.Alg, err = readAlg(members); err != nil {
		return h, err
	}
	if h.Nonce, err = readString(members, "nonce"); err != nil {
		return h, err
	}
	if err := checkNonce(h.Nonce); err != nil {
		return h, err
	}
	if h.URL, err = readURL(members, "url"); err != nil {
		return h, err
	}
	if hasKid {
		h.Kid, err = readURL(members, "kid")
		return h, err
	}
	h.JWK, err = readHeaderJWK(members, h.Alg)
	return h, err
}

func parseKeyChangeHeader(segment string) (KeyChangeHeader, error) {
	var h KeyChangeHeader
	members, err := readMembers(segment)
	if err != nil {
		return h, err
	}
	_, hasJWK := members["jwk"]
	if len(members) != 3 || !hasJWK {
		return h, fmt.Errorf("%w: header must have exactly alg, jwk and url", ErrMalformed)
	}
	if h.Alg, err = readAlg(members); err != nil {
		return h, err
	}
	if h.URL, err = readURL(members, "url"); err != nil {
		return h, err
	}
	h.JWK, err = readHeaderJWK(members, h.Alg)
	return h, err
}

// readMembers decodes a protected header in I-JSON; its members are read by their exact names.
func readMembers(segment string) (map[string]json.RawMessage, error) {
	encoded, err := decode("header", segment)
	if err != nil {
		return nil, err
	}
	if err := ijson.Check(encoded); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil || members == nil {
		return nil, fmt.Errorf("%w: header is not a JSON object", ErrMalformed)
	}
	return members, nil
}

// readString reads a member that must be a JSON string; null is not one.
func readString(members map[string]json.RawMessage, name string) (string, error) {
	raw, ok := members[name]
	var s string
	if !ok || len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%w: %s must be a string", ErrMalformed, name)
	}
	return s, nil
}

func readAlg(members map[string]json.RawMessage) (string, error) {
	alg, err := readString(members, "alg")
	if err != nil {
		return "", err
	}
	if alg != jws.AlgEdDSA && alg != jws.AlgES256 {
		return "", fmt.Errorf("%w: algorithm %s", ErrMalformed, quote(alg))
	}
	return alg, nil
}

func readURL(members map[string]json.RawMessage, name string) (string, error) {
	s, err := readString(members, name)
	if err != nil {
		return "", err
	}
	return s, checkURL(name, s)
}

// readHeaderJWK reads the key of a header in the form of $defs/jwk of the enrollment schema;
// alg has to match its type. White space between its members is allowed, as anywhere in the
// header, so it is removed before jws.ParseJWK applies its bound.
func readHeaderJWK(members map[string]json.RawMessage, alg string) (crypto.PublicKey, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, members["jwk"]); err != nil {
		return nil, fmt.Errorf("%w: jwk: %v", ErrMalformed, err)
	}
	key, err := jws.ParseJWK(compact.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: jwk: %s", ErrMalformed, reason(err, jws.ErrKey))
	}
	if got, _ := jws.KeyAlgorithm(key); got != alg {
		return nil, fmt.Errorf("%w: algorithm %s for a %s key", ErrMalformed, alg, got)
	}
	return key, nil
}

func checkNonce(nonce string) error {
	decoded, err := jws.DecodeSegment(nonce)
	if err != nil || len(nonce) > maxNonceChars || len(decoded) < minNonceBytes {
		return fmt.Errorf("%w: nonce %s is not base64url of at least %d bytes", ErrMalformed, quote(nonce), minNonceBytes)
	}
	return nil
}

func checkURL(name, s string) error {
	if len(s) > maxURLChars || !httpsURL.MatchString(s) {
		return fmt.Errorf("%w: %s %s is not an HTTPS URL of the schema", ErrMalformed, name, quote(s))
	}
	return nil
}

// checkPayload: a payload is a JSON object in I-JSON, or empty for a read.
func checkPayload(payload []byte, emptyAllowed bool) error {
	if len(payload) == 0 {
		if emptyAllowed {
			return nil
		}
		return fmt.Errorf("%w: no payload", ErrMalformed)
	}
	if err := ijson.Check(payload); err != nil {
		return fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return fmt.Errorf("%w: payload is not a JSON object", ErrMalformed)
	}
	return nil
}

// quote quotes a value from a request for an error message, at most its first maxQuotedBytes
// bytes, so that a sender cannot fill logs through the errors.
func quote(s string) string {
	if len(s) <= maxQuotedBytes {
		return strconv.Quote(s)
	}
	return strconv.Quote(s[:maxQuotedBytes]) + "..."
}

// sameKey reports whether a and b are the same public key; a nil key is no key.
func sameKey(a, b crypto.PublicKey) bool {
	if e, ok := a.(*ecdsa.PublicKey); ok && e == nil {
		return false
	}
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}
