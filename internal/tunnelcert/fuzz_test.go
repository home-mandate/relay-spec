// SPDX-License-Identifier: Apache-2.0

package tunnelcert

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const fuzzTrustDomain = "relay.example.net"

// FuzzHomeIDOf feeds the value of a subject alternative name extension, which a gateway chooses
// for its certificate request, to the check of the SPIFFE ID (section 4.1). An accepted value is
// exactly the DER of one URI spiffe://<trust domain>/home/<home ID>/gateway.
func FuzzHomeIDOf(f *testing.F) {
	good, err := SANValue("spiffe://" + fuzzTrustDomain + "/home/" + strings.Repeat("a", homeIDLength) + "/gateway")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte{})
	f.Add(append(good, 0))
	f.Fuzz(func(t *testing.T, value []byte) {
		c := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSAN, Value: value}}}
		home, err := homeIDOf(c, fuzzTrustDomain)
		if err != nil {
			return
		}
		if len(home) != homeIDLength || strings.Trim(home, homeIDAlphabet) != "" {
			t.Fatalf("accepted home ID %q", home)
		}
		want, err := SANValue("spiffe://" + fuzzTrustDomain + "/home/" + home + "/gateway")
		if err != nil || string(want) != string(value) {
			t.Fatalf("accepted %x, which is not the DER of the SPIFFE ID of home %q", value, home)
		}
	})
}

// FuzzCheckCSR feeds certificate signing requests, which a gateway sends to the operator, to
// CheckCSR (section 5.4). It never panics, and an accepted request parses and carries a key
// other than the installation key.
func FuzzCheckCSR(f *testing.F) {
	installation := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	// The requests of the conformance cases, valid and invalid, as seeds.
	data, err := os.ReadFile("../../conformance/csr-v0.json")
	if err != nil {
		f.Fatal(err)
	}
	var file struct {
		Cases []struct {
			CSR string `json:"csr"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		f.Fatal(err)
	}
	for _, c := range file.Cases {
		if der, err := base64.RawURLEncoding.DecodeString(c.CSR); err == nil {
			f.Add(der)
		}
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		key, err := CheckCSR(der, installation, nil)
		if err != nil {
			return
		}
		if _, err := x509.ParseCertificateRequest(der); err != nil {
			t.Fatalf("accepted a request that does not parse: %v", err)
		}
		if k, ok := key.(ed25519.PublicKey); ok && k.Equal(installation) {
			t.Fatal("accepted the installation key as the key of a tunnel certificate")
		}
	})
}
