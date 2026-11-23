// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/refca"
	"github.com/home-mandate/relay-spec/internal/refop"
)

// issuanceResult is the class issuance of a report.
func issuanceResult(t *testing.T, res Result) *ClassResult {
	t.Helper()
	c := res.Report.Classes[ClassIssuance]
	if c == nil {
		t.Fatal("no class issuance in the report")
	}
	return c
}

// TestTheCleanReferencePassesIssuance: against the reference CA in production, the tool obtains
// one certificate for the standard name of the second installation, sees both refusals and
// valid SCTs, deactivates its two accounts, and leaves only the checks of -ct-verify.
func TestTheCleanReferencePassesIssuance(t *testing.T) {
	r, env := serve(t, refop.Config{})
	s := enrollSettings(t, r, ClassIssuance)
	res := RunWith(ctx(t), s, env)
	c := issuanceResult(t, res)
	if len(res.Report.Failures) != 0 || c.Passed != 4 || c.Skipped != 2 || c.Failed != 0 || c.Conforms {
		t.Fatalf("failures %+v, issuance %+v, incomplete %v", res.Report.Failures, c, res.Report.Incomplete)
	}
	if !slices.Contains(res.Report.Incomplete, reasonCTVerify) {
		t.Errorf("incomplete %v", res.Report.Incomplete)
	}
	ca := r.Operator.CA()
	issued := ca.Issued()
	if len(issued) != 1 || !strings.HasSuffix(issued[0].DNSNames[0], "."+refop.DefaultNameDomain) {
		t.Errorf("issued %d certificates", len(issued))
	}
	if ca.Accounts() != 2 || ca.ActiveAccounts() != 0 {
		t.Errorf("%d accounts, %d still active", ca.Accounts(), ca.ActiveAccounts())
	}
	if res.Report.Installations != (Installations{Created: 2, Unpaired: 2}) {
		t.Errorf("installations %+v", res.Report.Installations)
	}
	if len(res.Report.NotChecked) < 6 {
		t.Errorf("not checked %v", res.Report.NotChecked)
	}
}

// TestACAThatKeepsTheChallengeStillJudgesBothRefusals: a CA whose resolver keeps the TXT
// records of the challenge for their TTL (60 seconds at the reference, a second being TTLUnit)
// must not see the value of an earlier order when it validates the refusals.
func TestACAThatKeepsTheChallengeStillJudgesBothRefusals(t *testing.T) {
	r, env := serve(t, refop.Config{CATXTCache: 60 * testTiming().TTLUnit})
	s := enrollSettings(t, r, ClassIssuance)
	res := RunWith(ctx(t), s, env)
	c := issuanceResult(t, res)
	if len(res.Report.Failures) != 0 || c.Passed != 4 || c.Skipped != 2 {
		t.Fatalf("failures %+v, issuance %+v, incomplete %v", res.Report.Failures, c, res.Report.Incomplete)
	}
}

// TestALongChallengeTTLLeavesTheRefusalsUnjudged: the tool waits out the TTL of the challenge
// records for at most ten minutes; with a longer TTL it orders no refusal and says why.
func TestALongChallengeTTLLeavesTheRefusalsUnjudged(t *testing.T) {
	r, env := serve(t, refop.Config{ChallengeTTL: maxCacheWait + 1})
	s := enrollSettings(t, r, ClassIssuance)
	res := RunWith(ctx(t), s, env)
	c := issuanceResult(t, res)
	if len(res.Report.Failures) != 0 || c.Passed != 2 || c.Skipped != 4 {
		t.Fatalf("failures %+v, issuance %+v, incomplete %v", res.Report.Failures, c, res.Report.Incomplete)
	}
	if !slices.ContainsFunc(res.Report.Incomplete, func(s string) bool { return strings.Contains(s, "TTL of 601 seconds") }) {
		t.Errorf("incomplete %v", res.Report.Incomplete)
	}
	if ca := r.Operator.CA(); ca.Accounts() != 1 || len(ca.Issued()) != 1 {
		t.Errorf("%d accounts, %d certificates", ca.Accounts(), len(ca.Issued()))
	}
}

// TestStagingChecksNoCertificateTransparency: a run against the test environment of the CA
// checks issuance and refusals, and says that CT needs the production environment.
func TestStagingChecksNoCertificateTransparency(t *testing.T) {
	r, env := serve(t, refop.Config{})
	s := enrollSettings(t, r, ClassIssuance)
	s.ACMEProduction = false
	env.CAs[0].Production = Endpoint{Directory: "https://production.invalid/directory", AccountPrefix: "https://production.invalid/acct/"}
	res := RunWith(ctx(t), s, env)
	c := issuanceResult(t, res)
	if len(res.Report.Failures) != 0 || c.Passed != 3 || c.Skipped != 3 {
		t.Fatalf("failures %+v, issuance %+v", res.Report.Failures, c)
	}
	if !slices.Contains(res.Report.Incomplete, reasonStaging) || slices.Contains(res.Report.Incomplete, reasonCTVerify) {
		t.Errorf("incomplete %v", res.Report.Incomplete)
	}
}

// TestEachBrokenCAFailsExactlyItsCheck: every defect of the reference CA, and every answer of
// the operator that only the CA sees, fails the check meant to catch it, and no other check.
func TestEachBrokenCAFailsExactlyItsCheck(t *testing.T) {
	for name, tt := range map[string]struct {
		op         refop.Fault
		ca         refca.Fault
		want       string
		incomplete string
	}{
		"I1 ignores accounturi":       {ca: refca.IgnoreAccountURI, want: CheckIssuanceForeign},
		"I2 ignores issuewild":        {ca: refca.IgnoreIssuewild, want: CheckIssuanceWildcard},
		"I3 a bad SCT":                {ca: refca.BadSCT, want: CheckIssuanceSCT},
		"I4 one log":                  {ca: refca.OneLog, want: CheckIssuanceSCT},
		"I5 no SCT":                   {ca: refca.NoSCT, want: CheckIssuanceSCT},
		"I6 SCTs of another cert":     {ca: refca.SCTOfOtherCertificate, want: CheckIssuanceSCT},
		"D11 the CA sees another CAA": {op: refop.CASeesOtherCAA, want: CheckIssuanceForeign},
		"D12 the CA sees no TXT":      {op: refop.CASeesNoChallenge, want: CheckIssuanceIssue, incomplete: "for another reason than CAA"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r, env := serve(t, refop.Config{Faults: tt.op, CAFaults: tt.ca})
			res := RunWith(ctx(t), enrollSettings(t, r, ClassIssuance), env)
			if got := failures(res); !slices.Equal(got, []string{"live:" + tt.want}) {
				t.Errorf("failed %v, want %s", got, tt.want)
			}
			if tt.incomplete != "" && !strings.Contains(strings.Join(res.Report.Incomplete, "|"), tt.incomplete) {
				t.Errorf("incomplete %v", res.Report.Incomplete)
			}
			if res.Exit != ExitFails || res.Report.Installations.Created != res.Report.Installations.Unpaired {
				t.Errorf("exit %d, installations %+v", res.Exit, res.Report.Installations)
			}
		})
	}
}

// TestIssuanceWithoutAUsableCA: without endpoints for a CA of acme_cas, or with a CA that cannot
// be reached, the class issuance is incomplete and the other classes run as before.
func TestIssuanceWithoutAUsableCA(t *testing.T) {
	for name, change := range map[string]func(*Env){
		"no CA known": func(e *Env) { e.CAs = nil },
		"unreachable": func(e *Env) {
			e.CAs[0].Production = Endpoint{Directory: "https://" + closedPort(t) + "/directory", AccountPrefix: "https://x.invalid/acct/"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, env := serve(t, refop.Config{})
			change(&env)
			res := RunWith(ctx(t), enrollSettings(t, r, ClassEnrollment, ClassIssuance), env)
			if len(res.Report.Failures) != 0 || !res.Report.Classes[ClassEnrollment].Conforms {
				t.Fatalf("failures %+v, enrollment %+v", res.Report.Failures, res.Report.Classes[ClassEnrollment])
			}
			c := issuanceResult(t, res)
			if c.Passed != 0 || c.Conforms {
				t.Errorf("issuance %+v", c)
			}
			text := strings.Join(res.Report.Incomplete, "|")
			if !strings.Contains(text, "issuance") || res.Exit != ExitIncomplete {
				t.Errorf("exit %d, incomplete %v", res.Exit, res.Report.Incomplete)
			}
			if n := len(r.Operator.CA().Issued()); n != 0 {
				t.Errorf("%d certificates issued", n)
			}
		})
	}
}

// TestIssuanceNeedsTheSecondInstallation: with one code the class issuance is skipped.
func TestIssuanceNeedsTheSecondInstallation(t *testing.T) {
	r, env := serve(t, refop.Config{})
	s := enrollSettings(t, r, ClassIssuance)
	s.Codes = s.Codes[:1]
	res := RunWith(ctx(t), s, env)
	if c := issuanceResult(t, res); c.Passed != 0 || c.Failed != 0 || res.Exit != ExitIncomplete {
		t.Errorf("issuance %+v, exit %d", c, res.Exit)
	}
	if r.Operator.CA().Accounts() != 0 {
		t.Error("an account was created")
	}
}

func TestFetchLogListChecksTheSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	list := []byte(`{"version":"1","log_list_timestamp":"2026-11-23T00:00:00Z","operators":[{"name":"A"}]}`)
	sig := signOver(t, key, list)
	for name, tt := range map[string]struct {
		list, sig []byte
		status    int
		ok        bool
	}{
		"signed":         {list, sig, 200, true},
		"another list":   {append(slices.Clone(list), ' '), sig, 200, false},
		"no signature":   {list, nil, 200, false},
		"not found":      {list, sig, 404, false},
		"too large":      {append(slices.Clone(list), make([]byte, ctlog.MaxListBytes)...), sig, 200, false},
		"not a log list": {[]byte(`{}`), signOver(t, key, []byte(`{}`)), 200, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				if strings.HasSuffix(r.URL.Path, ".sig") {
					_, _ = w.Write(tt.sig)
					return
				}
				_, _ = w.Write(tt.list)
			})
			web, base := webFor(t, h, testTiming())
			got, err := fetchLogList(ctx(t), web, base+"/log_list.json", base+"/log_list.sig", &key.PublicKey)
			if (err == nil) != tt.ok || (tt.ok && got == nil) {
				t.Errorf("list %v, error %v", got != nil, err)
			}
		})
	}
}

func signOver(t *testing.T, key *rsa.PrivateKey, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// TestDefaultCAsAreTheOnesOfTheCAList: the endpoints the tool uses for a CA are the ones cas.md
// lists for it, and the command uses them and the log list of Google.
func TestDefaultCAsAreTheOnesOfTheCAList(t *testing.T) {
	data, err := os.ReadFile("../../cas.md")
	if err != nil {
		t.Fatal(err)
	}
	cas := string(data)
	for _, ca := range DefaultCAs {
		for _, v := range []string{ca.Identity, ca.Production.Directory, ca.Production.AccountPrefix, ca.Staging.Directory, ca.Staging.AccountPrefix} {
			if !strings.Contains(cas, "`"+v+"`") {
				t.Errorf("cas.md does not list %s", v)
			}
		}
	}
	if env := productionEnv(); len(env.CAs) == 0 || env.LogList != nil {
		t.Error("the command does not use the CAs of cas.md and the log list of Google")
	}
}
