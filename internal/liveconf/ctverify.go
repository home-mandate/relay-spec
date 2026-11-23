// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/home-mandate/relay-spec/internal/ctlog"
)

const (
	// ctFileVersion is the version of the file for -ct-verify.
	ctFileVersion = 1
	// maxCTFileBytes limits what -ct-verify reads.
	maxCTFileBytes = 1 << 20
	// ctChecks is how many checks -ct-verify makes.
	ctChecks = 2
	// ctFileMode keeps the file to its owner, like the state file.
	ctFileMode = 0o600
)

// ctCertificate is the certificate of the class issuance that -ct-verify checks.
type ctCertificate struct {
	leaf, issuer *x509.Certificate
	name         string
}

// ctFile is what a production run leaves for -ct-verify: the report before the verdicts that
// need the whole run, and what they need. It holds no key.
type ctFile struct {
	Version  int    `json:"version"`
	Operator string `json:"operator"`
	Name     string `json:"standard_name"`
	// Since is the start of the run, before the pairing.
	Since       time.Time `json:"since"`
	Certificate []byte    `json:"certificate"`
	Issuer      []byte    `json:"issuer"`
	Codes       int       `json:"codes"`
	OwnDomain   bool      `json:"own_domain"`
	Classes     []string  `json:"classes"`
	Report      Report    `json:"report"`
}

// ctPath is the file for -ct-verify next to the state file.
func ctPath(statePath string) string {
	return strings.TrimSuffix(statePath, ".json") + ".ct.json"
}

// writeCTFile writes the file for -ct-verify if the run obtained a certificate in production,
// and says so in the message. It returns the path, or "".
func (r *run) writeCTFile() string {
	if r.ct == nil || r.statePath == "" {
		return ""
	}
	f := ctFile{Version: ctFileVersion, Operator: r.s.Operator, Name: r.ct.name, Since: r.started.UTC(),
		Certificate: r.ct.leaf.Raw, Issuer: r.ct.issuer.Raw, Codes: len(r.s.Codes), OwnDomain: r.s.OwnDomain != "",
		Classes: r.s.Classes, Report: r.rep}
	data, err := json.MarshalIndent(f, "", "  ")
	path := ctPath(r.statePath)
	if err == nil {
		err = writeNew(path, data)
	}
	text := "run relay-conformance -ct-verify " + strconv.Quote(path) +
		" once the logs of the certificate had their maximum merge delay (at most a day)"
	if err != nil {
		path, text = "", "the file for -ct-verify could not be written"
	}
	r.message = strings.TrimPrefix(r.message+"; "+text, "; ")
	return path
}

// writeNew writes a new file with ctFileMode; a file or link at the path from an earlier run is
// removed first, so that neither its mode nor its target is used.
func writeNew(path string, data []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, ctFileMode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

// failedCheck reports whether a check of the run failed.
func (r *run) failedCheck(id string) bool {
	return slices.ContainsFunc(r.rep.Failures, func(f Failure) bool { return f.ID == id })
}

// CTVerifyWith completes a production run with the file it wrote (RELAY-v0 section 8.3): it
// checks the inclusion of the certificate in the logs of its SCTs and the snapshot of
// Certificate Transparency, and gives the report of the whole run.
func CTVerifyWith(ctx context.Context, s Settings, env Env) Result {
	s, err := s.Validate()
	if err == nil && s.CTVerifyPath == "" {
		err = usagef("-ct-verify needs the file of a run")
	}
	if err != nil {
		return Result{Exit: ExitUsage, Message: err.Error()}
	}
	f, leaf, issuer, err := readCTFile(s.CTVerifyPath)
	if err != nil {
		return Result{Exit: ExitUsage, Message: err.Error()}
	}
	codes := make([]string, f.Codes)
	own := ""
	if f.OwnDomain {
		own = "own"
	}
	r := &run{s: Settings{Operator: f.Operator, Classes: f.Classes, Codes: codes, OwnDomain: own, ACMEProduction: true},
		env: env, web: newWeb(env), rep: f.Report}
	r.rep.CTVerified = time.Now().UTC().Format(dateLayout)
	r.rep.Incomplete = slices.DeleteFunc(r.rep.Incomplete, func(t string) bool { return t == reasonCTVerify })
	c := r.rep.Classes[ClassIssuance]
	c.Cases -= ctChecks
	c.Skipped -= ctChecks
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	r.verifyInclusion(ctx, leaf, issuer)
	r.verifySnapshot(ctx, f, leaf)
	res := r.result()
	if slices.ContainsFunc(res.Report.Incomplete, func(t string) bool { return strings.Contains(t, "-ct-verify again") }) {
		res.Message = "run relay-conformance -ct-verify " + strconv.Quote(s.CTVerifyPath) + " again later"
	}
	return res
}

// readCTFile reads the file of a run that waits for -ct-verify.
func readCTFile(path string) (ctFile, *x509.Certificate, *x509.Certificate, error) {
	bad := func(what string) error {
		return usagef("%s is not a file of a run for -ct-verify: %s", strconv.Quote(path), what)
	}
	fh, err := os.Open(path)
	if err != nil {
		return ctFile{}, nil, nil, bad("it cannot be read")
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxCTFileBytes+1))
	if err != nil || len(data) > maxCTFileBytes {
		return ctFile{}, nil, nil, bad("it cannot be read or is too large")
	}
	var f ctFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return ctFile{}, nil, nil, bad("not JSON of this tool")
	}
	if f.Version != ctFileVersion {
		return ctFile{}, nil, nil, bad("another version")
	}
	leaf, err1 := x509.ParseCertificate(f.Certificate)
	issuer, err2 := x509.ParseCertificate(f.Issuer)
	c := f.Report.Classes[ClassIssuance]
	if err1 != nil || err2 != nil || c == nil || c.Skipped < ctChecks || c.Cases < c.Skipped || f.Codes < 0 || f.Codes > MaxCodes ||
		!ValidDomain(f.Name) || f.Report.Classes == nil {
		return ctFile{}, nil, nil, bad("it does not wait for -ct-verify")
	}
	return f, leaf, issuer, nil
}

// fetcher lets package ctlog fetch through the Web of the run.
func (r *run) fetcher() ctlog.Fetcher {
	return func(ctx context.Context, url string, limit int64) (int, []byte, error) {
		got, err := r.web.get(ctx, url, limit)
		if err == nil && got.Over {
			err = errors.New("the answer is too large")
		}
		return got.Status, got.Body, err
	}
}

// verifyInclusion asks every log of the list that gave the certificate an SCT whether it
// includes the certificate (RELAY-v0 section 8.3).
func (r *run) verifyInclusion(ctx context.Context, leaf, issuer *x509.Certificate) {
	list, err := r.logList(ctx)
	scts, serr := ctlog.SCTsOf(leaf)
	if err != nil || serr != nil {
		r.skip(ClassIssuance)
		r.incomplete("the log list could not be fetched and verified, so the inclusion was not checked; run -ct-verify again")
		return
	}
	var problems, silent, stale []string
	var due time.Time
	checked := 0
	for i, sct := range scts {
		lg, _ := list.Find(sct.LogID)
		if lg == nil {
			continue
		}
		checked++
		name := fmt.Sprintf("SCT %d", i+1)
		got, err := ctlog.CheckInclusion(ctx, r.fetcher(), lg, sct, leaf, issuer)
		deadline := sct.Time().Add(time.Duration(lg.MMD) * time.Second)
		switch {
		case errors.Is(err, ctlog.ErrBadLog):
			problems = append(problems, name+": the proof of the log does not lead to its tree head")
		case err != nil:
			// No answer, or a tree head that does not verify with the key of the list: that says
			// nothing about the entry.
			silent = append(silent, name)
		case got.Included:
		case got.TreeTime.Before(deadline) && time.Now().After(deadline):
			stale = append(stale, name)
		case got.TreeTime.Before(deadline):
			if deadline.After(due) {
				due = deadline
			}
		default:
			problems = append(problems, name+": the log does not include the certificate after its maximum merge delay")
		}
	}
	switch {
	case len(problems) > 0:
		r.fail(ClassIssuance, CheckIssuanceInclusion, strings.Join(problems, "; "), titleOf(CheckIssuanceInclusion))
	case checked == 0:
		r.skip(ClassIssuance)
		r.incomplete("no SCT of the certificate is of a log of the log list, so the inclusion was not checked")
	case len(silent) > 0:
		r.skip(ClassIssuance)
		r.incomplete("the logs of " + strings.Join(silent, ", ") + " did not answer with a tree head that verifies; run -ct-verify again")
	case len(stale) > 0:
		r.skip(ClassIssuance)
		r.incomplete("the logs of " + strings.Join(stale, ", ") + " serve no tree head from after their maximum merge delay; run -ct-verify again")
	case !due.IsZero():
		r.skip(ClassIssuance)
		r.incomplete("the logs may include the certificate until " + due.UTC().Format(time.RFC3339) + "; run -ct-verify again then")
	default:
		r.pass(ClassIssuance)
	}
}
