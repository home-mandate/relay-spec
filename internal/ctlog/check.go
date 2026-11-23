// SPDX-License-Identifier: Apache-2.0

package ctlog

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// MinOperators is how many log operators the valid SCTs of a certificate come from at least.
const MinOperators = 2

// maxDescription limits the description of a log in a problem.
const maxDescription = 60

// Check returns what is wrong with the SCTs embedded in the leaf, which the issuer signed, by
// the list: there is none; an SCT of a log of the list is not version 1, its signature does not
// verify, its log was not usable at its time, or the leaf's notAfter is outside the log's
// temporal interval; or fewer than MinOperators operators of the list gave a valid SCT. SCTs
// of logs that the list does not hold are not used. An empty result means the SCTs show that
// the certificate was submitted to logs of the list (RELAY-v0 section 6.6).
func Check(leaf, issuer *x509.Certificate, list *List) []string {
	scts, err := SCTsOf(leaf)
	if err != nil {
		return []string{"the certificate has no SCT"}
	}
	tbs, err := PrecertTBS(leaf)
	if err != nil {
		return []string{"the TBSCertificate of the certificate cannot be read"}
	}
	var problems []string
	operators := map[string]bool{}
	for i, s := range scts {
		lg, operator := list.Find(s.LogID)
		if lg == nil {
			continue
		}
		if problem := judge(s, lg, leaf, tbs, issuer.RawSubjectPublicKeyInfo); problem != "" {
			problems = append(problems, fmt.Sprintf("SCT %d (%s) %s", i+1, describe(lg), problem))
			continue
		}
		operators[operator] = true
	}
	if len(operators) < MinOperators {
		problems = append(problems, fmt.Sprintf("valid SCTs of fewer than two log operators of the list (%d)", len(operators)))
	}
	return problems
}

func judge(s SCT, lg *Log, leaf *x509.Certificate, tbs, issuerSPKI []byte) string {
	in := lg.TemporalInterval
	switch {
	case s.Version != 0:
		return "has a version other than v1"
	case !s.verify(lg.key, tbs, issuerSPKI):
		return "has a signature that does not verify"
	case !lg.usableAt(s.Time()):
		return "is of a log that was not usable at its time"
	case in != nil && (leaf.NotAfter.Before(in.StartInclusive) || !leaf.NotAfter.Before(in.EndExclusive)):
		return "is of a log whose temporal interval does not hold the notAfter of the certificate"
	}
	return ""
}

// describe names a log by its description, in printable ASCII and at most maxDescription bytes.
func describe(lg *Log) string {
	d := strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, lg.Description)
	return d[:min(len(d), maxDescription)]
}
