// SPDX-License-Identifier: Apache-2.0

// Package ctlog reads what the class issuance of the live test needs from Certificate
// Transparency (RELAY-v0 sections 6.6, 6.7 and 8.3): the signed log list of Google (version 3),
// the SCTs embedded in a certificate, and whether they show that the certificate was submitted
// to logs of that list. It also signs SCTs, which the reference CA of the tests embeds.
package ctlog

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/home-mandate/spec/ijson"
)

// Where the tool fetches the log list and its signature (RELAY-v0 section 8.3).
const (
	ListURL      = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	SignatureURL = "https://www.gstatic.com/ct/log_list/v3/log_list.sig"
	// MaxListBytes limits the log list; the list of 2026-11-23 has 70 KB.
	MaxListBytes = 1 << 20
	// MaxSignatureBytes limits its signature, which has 512 bytes for the key of 4096 bits.
	MaxSignatureBytes = 1 << 10
)

// googlePEM is the key that signs the log list, from
// https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem (fetched 2026-11-23).
const googlePEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv
HHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq
fUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L
rmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+
i/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF
bLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S
IXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox
K0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe
/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF
4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+
+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS
1w22i9uGHMn/uGQKo28u7AsCAwEAAQ==
-----END PUBLIC KEY-----
`

// GoogleKey returns the key that signs the log list.
func GoogleKey() *rsa.PublicKey {
	block, _ := pem.Decode([]byte(googlePEM))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("ctlog: the key of the log list does not parse")
	}
	return key.(*rsa.PublicKey)
}

// ErrList is returned for a log list that cannot be used.
var ErrList = errors.New("ctlog: not a usable log list")

// VerifySignature checks the signature of the log list: RSASSA-PKCS1-v1_5 with SHA-256 over
// the bytes of the list as they were fetched.
func VerifySignature(list, sig []byte, key *rsa.PublicKey) error {
	digest := sha256.Sum256(list)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("%w: the signature does not verify", ErrList)
	}
	return nil
}

// List is a log list of version 3.
type List struct {
	Version   string     `json:"version"`
	Timestamp time.Time  `json:"log_list_timestamp"`
	Operators []Operator `json:"operators"`
}

// Operator is an operator of logs: those that follow RFC 6962 and the tiled ones of Static CT.
type Operator struct {
	Name      string `json:"name"`
	Logs      []Log  `json:"logs"`
	TiledLogs []Log  `json:"tiled_logs"`
}

// Log is one log of the list.
type Log struct {
	Description   string `json:"description"`
	LogID         []byte `json:"log_id"`
	Key           []byte `json:"key"`
	MMD           int    `json:"mmd"`
	URL           string `json:"url,omitempty"`
	SubmissionURL string `json:"submission_url,omitempty"`
	MonitoringURL string `json:"monitoring_url,omitempty"`
	// State has exactly one member: pending, qualified, usable, readonly, retired or rejected.
	State            map[string]StateSince `json:"state"`
	TemporalInterval *Interval             `json:"temporal_interval,omitempty"`

	key crypto.PublicKey
}

// StateSince is when a log entered its state.
type StateSince struct {
	Timestamp time.Time `json:"timestamp"`
}

// Interval is the range of notAfter that a sharded log accepts.
type Interval struct {
	StartInclusive time.Time `json:"start_inclusive"`
	EndExclusive   time.Time `json:"end_exclusive"`
}

// states are the states of a log.
var states = []string{"pending", "qualified", "usable", "readonly", "retired", "rejected"}

// ParseList parses a log list. A log whose ID is not the digest of its key, or whose key is
// neither ECDSA P-256 nor RSA, is left out: an SCT of it cannot be checked.
func ParseList(data []byte) (*List, error) {
	if len(data) > MaxListBytes {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrList, MaxListBytes)
	}
	if err := ijson.Check(data); err != nil {
		return nil, fmt.Errorf("%w: not I-JSON", ErrList)
	}
	var l List
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&l); err != nil || dec.More() {
		return nil, fmt.Errorf("%w: not a list of version 3", ErrList)
	}
	if len(l.Operators) == 0 {
		return nil, fmt.Errorf("%w: no operators", ErrList)
	}
	for i := range l.Operators {
		op := &l.Operators[i]
		var err error
		if op.Logs, err = usableKeys(op.Logs); err != nil {
			return nil, err
		}
		if op.TiledLogs, err = usableKeys(op.TiledLogs); err != nil {
			return nil, err
		}
	}
	return &l, nil
}

func usableKeys(logs []Log) ([]Log, error) {
	out := make([]Log, 0, len(logs))
	for _, lg := range logs {
		if len(lg.State) != 1 {
			return nil, fmt.Errorf("%w: a log without exactly one state", ErrList)
		}
		for name := range lg.State {
			if !slices.Contains(states, name) {
				return nil, fmt.Errorf("%w: a log with an unknown state", ErrList)
			}
		}
		digest := sha256.Sum256(lg.Key)
		key, err := x509.ParsePKIXPublicKey(lg.Key)
		if err != nil || !bytes.Equal(digest[:], lg.LogID) || !supported(key) {
			continue
		}
		lg.key = key
		out = append(out, lg)
	}
	return out, nil
}

func supported(key crypto.PublicKey) bool {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256()
	case *rsa.PublicKey:
		return true
	}
	return false
}

// Find returns the log with the ID and the name of its operator, or nil.
func (l *List) Find(id [32]byte) (*Log, string) {
	for i := range l.Operators {
		op := &l.Operators[i]
		for _, logs := range [][]Log{op.Logs, op.TiledLogs} {
			for j := range logs {
				if bytes.Equal(logs[j].LogID, id[:]) {
					return &logs[j], op.Name
				}
			}
		}
	}
	return nil, ""
}

// usableAt reports whether an SCT of the log with the time t counts: the log is qualified or
// usable, or it became read-only or retired after t.
func (lg *Log) usableAt(t time.Time) bool {
	for name, since := range lg.State {
		switch name {
		case "qualified", "usable":
			return true
		case "readonly", "retired":
			return t.Before(since.Timestamp)
		}
	}
	return false
}
