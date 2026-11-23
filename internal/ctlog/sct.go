// SPDX-License-Identifier: Apache-2.0

package ctlog

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OIDSCTList is the extension with the embedded SCTs (RFC 6962 section 3.3).
var OIDSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// Values of an SCT (RFC 6962 section 3.2, RFC 5246 section 7.4.1.4.1).
const (
	hashSHA256 = 4
	sigRSA     = 1
	sigECDSA   = 3
	// entryPrecert is the entry type of an SCT that a CA embeds.
	entryPrecert = 1
	logIDBytes   = 32
)

// ErrSCT is returned for SCTs that cannot be read.
var ErrSCT = errors.New("ctlog: not a list of SCTs")

// SCT is a signed certificate timestamp (RFC 6962 section 3.2).
type SCT struct {
	Version    uint8
	LogID      [logIDBytes]byte
	Timestamp  uint64
	Extensions []byte
	HashAlg    uint8
	SigAlg     uint8
	Signature  []byte
}

// Time returns the timestamp of the SCT.
func (s SCT) Time() time.Time { return time.UnixMilli(int64(s.Timestamp)) } //nolint:gosec // milliseconds since 1970 fit

// ParseSCTList parses the value of the extension OIDSCTList: an OCTET STRING that holds a
// SignedCertificateTimestampList with at least one SCT.
func ParseSCTList(ext []byte) ([]SCT, error) {
	var inner, list cryptobyte.String
	in := cryptobyte.String(ext)
	if !in.ReadASN1(&inner, cbasn1.OCTET_STRING) || !in.Empty() ||
		!inner.ReadUint16LengthPrefixed(&list) || !inner.Empty() || list.Empty() {
		return nil, ErrSCT
	}
	var out []SCT
	for !list.Empty() {
		var raw cryptobyte.String
		if !list.ReadUint16LengthPrefixed(&raw) {
			return nil, ErrSCT
		}
		s, ok := parseSCT(raw)
		if !ok {
			return nil, ErrSCT
		}
		out = append(out, s)
	}
	return out, nil
}

func parseSCT(raw cryptobyte.String) (SCT, bool) {
	var s SCT
	var id, ext, sig []byte
	ok := raw.ReadUint8(&s.Version) && raw.ReadBytes(&id, logIDBytes) && raw.ReadUint64(&s.Timestamp) &&
		readUint16Bytes(&raw, &ext) && raw.ReadUint8(&s.HashAlg) && raw.ReadUint8(&s.SigAlg) &&
		readUint16Bytes(&raw, &sig) && raw.Empty()
	copy(s.LogID[:], id)
	s.Extensions, s.Signature = ext, sig
	return s, ok
}

func readUint16Bytes(s *cryptobyte.String, out *[]byte) bool {
	var v cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&v) {
		return false
	}
	*out = append([]byte{}, v...)
	return true
}

// MarshalSCTList returns the value of the extension OIDSCTList for the SCTs.
func MarshalSCTList(scts []SCT) ([]byte, error) {
	if len(scts) == 0 {
		return nil, ErrSCT
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range scts {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(s.Version)
					b.AddBytes(s.LogID[:])
					b.AddUint64(s.Timestamp)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s.Extensions) })
					b.AddUint8(s.HashAlg)
					b.AddUint8(s.SigAlg)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s.Signature) })
				})
			}
		})
	})
	return b.Bytes()
}

// signedData is what the log signs for an SCT of a precertificate (RFC 6962 section 3.2).
func signedData(s SCT, tbs, issuerSPKI []byte) ([]byte, error) {
	keyHash := sha256.Sum256(issuerSPKI)
	var b cryptobyte.Builder
	b.AddUint8(s.Version)
	b.AddUint8(0) // signature_type certificate_timestamp
	b.AddUint64(s.Timestamp)
	b.AddUint16(entryPrecert)
	b.AddBytes(keyHash[:])
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s.Extensions) })
	return b.Bytes()
}

// SignPrecert returns the SCT a log with the key gives for a precertificate with the
// TBSCertificate tbs (without poison and SCTs) of the issuer with the SubjectPublicKeyInfo.
func SignPrecert(key crypto.Signer, tbs, issuerSPKI []byte, at time.Time) (SCT, error) {
	return SignPrecertWithExtensions(key, tbs, issuerSPKI, at, nil)
}

// SignPrecertWithExtensions is SignPrecert with SCT extensions, such as the leaf index of a
// tiled log.
func SignPrecertWithExtensions(key crypto.Signer, tbs, issuerSPKI []byte, at time.Time, ext []byte) (SCT, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return SCT{}, err
	}
	s := SCT{LogID: sha256.Sum256(der), Timestamp: uint64(at.UnixMilli()), HashAlg: hashSHA256, Extensions: ext} //nolint:gosec // after 1970
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		s.SigAlg = sigECDSA
	case *rsa.PublicKey:
		s.SigAlg = sigRSA
	default:
		return SCT{}, fmt.Errorf("%w: a log key of an unsupported type", ErrSCT)
	}
	data, err := signedData(s, tbs, issuerSPKI)
	if err != nil {
		return SCT{}, err
	}
	digest := sha256.Sum256(data)
	if s.Signature, err = key.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		return SCT{}, err
	}
	return s, nil
}

// verify checks the signature of the SCT over the precertificate with the key of its log.
func (s SCT) verify(key crypto.PublicKey, tbs, issuerSPKI []byte) bool {
	if s.HashAlg != hashSHA256 {
		return false
	}
	data, err := signedData(s, tbs, issuerSPKI)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(data)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return s.SigAlg == sigECDSA && ecdsa.VerifyASN1(k, digest[:], s.Signature)
	case *rsa.PublicKey:
		return s.SigAlg == sigRSA && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], s.Signature) == nil
	}
	return false
}

// SCTsOf returns the SCTs embedded in the certificate.
func SCTsOf(cert *x509.Certificate) ([]SCT, error) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(OIDSCTList) {
			return ParseSCTList(e.Value)
		}
	}
	return nil, fmt.Errorf("%w: the certificate has no SCT", ErrSCT)
}

var tagExtensions = cbasn1.Tag(3).Constructed().ContextSpecific()

// PrecertTBS returns the TBSCertificate of the certificate without the extension OIDSCTList:
// the TBSCertificate of the precertificate without its poison, which the logs signed.
func PrecertTBS(cert *x509.Certificate) ([]byte, error) {
	in := cryptobyte.String(cert.RawTBSCertificate)
	var tbs cryptobyte.String
	if !in.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, ErrSCT
	}
	found := false
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for !tbs.Empty() {
			var el cryptobyte.String
			var tag cbasn1.Tag
			if !tbs.ReadAnyASN1Element(&el, &tag) {
				b.SetError(ErrSCT)
				return
			}
			if tag != tagExtensions {
				b.AddBytes(el)
				continue
			}
			kept, removed, err := withoutSCTs(el)
			if err != nil {
				b.SetError(err)
				return
			}
			found = found || removed
			b.AddASN1(tagExtensions, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(kept) })
			})
		}
	})
	out, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: the certificate has no SCT", ErrSCT)
	}
	return out, nil
}

// withoutSCTs returns the extensions of the element [3] without the one with the SCTs, and
// whether that one was there.
func withoutSCTs(el cryptobyte.String) ([]byte, bool, error) {
	var explicit, exts cryptobyte.String
	if !el.ReadASN1(&explicit, tagExtensions) || !explicit.ReadASN1(&exts, cbasn1.SEQUENCE) {
		return nil, false, ErrSCT
	}
	var kept []byte
	removed := false
	for !exts.Empty() {
		var ext, body cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !exts.ReadASN1Element(&ext, cbasn1.SEQUENCE) {
			return nil, false, ErrSCT
		}
		body = ext
		if !body.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1ObjectIdentifier(&oid) {
			return nil, false, ErrSCT
		}
		if oid.Equal(OIDSCTList) {
			removed = true
			continue
		}
		kept = append(kept, ext...)
	}
	return kept, removed, nil
}
