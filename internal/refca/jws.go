// SPDX-License-Identifier: Apache-2.0

package refca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
)

// request is a verified request: the payload, the jwk of a new account or the account that
// signed it, and the ID of the resource.
type request struct {
	payload []byte
	jwk     *ecdsa.PublicKey
	acct    *account
	id      string
}

type jwsBody struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type protectedHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	JWK   json.RawMessage `json:"jwk"`
	Kid   string          `json:"kid"`
}

type ecJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

const (
	es256Bytes = 64
	coordBytes = 32
)

func malformed(detail string) *problem { return &problem{http.StatusBadRequest, "malformed", detail} }

// verify checks a flattened JWS with ES256 (RFC 8555 section 6.2): the nonce, the URL of the
// request, and the signature by the jwk (withJWK) or by the key of a valid account (kid).
func (c *CA) verify(r *http.Request, withJWK bool) (*request, *problem) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return nil, malformed("the body cannot be read")
	}
	var body jwsBody
	if json.Unmarshal(raw, &body) != nil || body.Protected == "" {
		return nil, malformed("not a flattened JWS")
	}
	hdrBytes, err1 := base64.RawURLEncoding.DecodeString(body.Protected)
	payload, err2 := base64.RawURLEncoding.DecodeString(body.Payload)
	sig, err3 := base64.RawURLEncoding.DecodeString(body.Signature)
	var hdr protectedHeader
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(hdrBytes, &hdr) != nil {
		return nil, malformed("the JWS cannot be decoded")
	}
	if hdr.Nonce == "" || !c.useNonce(hdr.Nonce) {
		return nil, &problem{http.StatusBadRequest, "badNonce", "the nonce is unknown or used"}
	}
	if hdr.Alg != "ES256" {
		return nil, &problem{http.StatusBadRequest, "badSignatureAlgorithm", "only ES256"}
	}
	if hdr.URL != c.url(r.URL.Path) {
		return nil, &problem{http.StatusUnauthorized, "unauthorized", "the url of the request does not match"}
	}
	req := &request{payload: payload}
	key, p := c.signer(hdr, withJWK, req)
	if p != nil {
		return nil, p
	}
	digest := sha256.Sum256([]byte(body.Protected + "." + body.Payload))
	if len(sig) != es256Bytes || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:coordBytes]), new(big.Int).SetBytes(sig[coordBytes:])) {
		return nil, malformed("the signature does not verify")
	}
	return req, nil
}

// signer returns the key that has to have signed the request: the jwk of a request for a new
// account, else the key of the valid account named by kid.
func (c *CA) signer(hdr protectedHeader, withJWK bool, req *request) (*ecdsa.PublicKey, *problem) {
	switch {
	case withJWK && hdr.Kid == "" && len(hdr.JWK) > 0:
		key := parseJWK(hdr.JWK)
		if key == nil {
			return nil, malformed("the jwk is no P-256 key")
		}
		req.jwk = key
		return key, nil
	case !withJWK && hdr.Kid != "" && len(hdr.JWK) == 0:
		acct := c.accountByKid(hdr.Kid)
		if acct == nil || !acct.valid(c) {
			return nil, &problem{http.StatusUnauthorized, "unauthorized", "no valid account"}
		}
		req.acct = acct
		return acct.key, nil
	}
	return nil, malformed("the request needs exactly one of jwk and kid as its kind demands")
}

func (a *account) valid(c *CA) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return a.status == "valid"
}

func parseJWK(raw json.RawMessage) *ecdsa.PublicKey {
	var j ecJWK
	if json.Unmarshal(raw, &j) != nil || j.Kty != "EC" || j.Crv != "P-256" {
		return nil
	}
	x, errX := base64.RawURLEncoding.DecodeString(j.X)
	y, errY := base64.RawURLEncoding.DecodeString(j.Y)
	if errX != nil || errY != nil || len(x) != coordBytes || len(y) != coordBytes {
		return nil
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil
	}
	return key
}

// thumbprint is the JWK thumbprint of the key (RFC 7638), as the key authorization uses it.
func thumbprint(key *ecdsa.PublicKey) string {
	raw := must(key.Bytes())
	b := base64.RawURLEncoding.EncodeToString
	canonical := `{"crv":"P-256","kty":"EC","x":"` + b(raw[1:1+coordBytes]) + `","y":"` + b(raw[1+coordBytes:]) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b(sum[:])
}

func (c *CA) accountByKid(kid string) *account {
	id, ok := strings.CutPrefix(kid, c.AccountPrefix())
	if !ok {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accounts[id]
}
