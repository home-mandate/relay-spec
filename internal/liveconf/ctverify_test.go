// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/home-mandate/relay-spec/internal/ctlog"
	"github.com/home-mandate/relay-spec/internal/refca"
	"github.com/home-mandate/relay-spec/internal/reflog"
	"github.com/home-mandate/relay-spec/internal/refop"
)

// issuanceRun runs the class issuance in production against the reference and returns the
// result with the file for -ct-verify.
func issuanceRun(t *testing.T, cfg refop.Config) (Result, Env) {
	t.Helper()
	r, env := serve(t, cfg)
	res := RunWith(ctx(t), enrollSettings(t, r, ClassIssuance), env)
	if res.CTFile == "" {
		t.Fatalf("no file for -ct-verify: %s, failures %+v, incomplete %v", res.Message, res.Report.Failures, res.Report.Incomplete)
	}
	return res, env
}

func verify(t *testing.T, res Result, env Env) Result {
	t.Helper()
	return CTVerifyWith(ctx(t), Settings{CTVerifyPath: res.CTFile, Version: "test"}, env)
}

// TestCTVerifyCompletesTheRun: the whole reference conforms once -ct-verify finds the
// certificate in both logs and no other certificate for the name.
func TestCTVerifyCompletesTheRun(t *testing.T) {
	r, env := serveFull(t, 0)
	res := RunWith(ctx(t), enrollSettings(t, r), env)
	if !waitsOnlyForCTVerify(res) || res.CTFile == "" || !strings.Contains(res.Message, "-ct-verify") {
		t.Fatalf("exit %d (%s), incomplete %v, file %q", res.Exit, res.Message, res.Report.Incomplete, res.CTFile)
	}
	info, err := os.Stat(res.CTFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v", err)
	}
	data := must(os.ReadFile(res.CTFile))
	for _, secret := range append([]string{"PRIVATE", "/enroll/installation/"}, refop.DefaultCodes...) {
		if strings.Contains(string(data), secret) {
			t.Errorf("the file holds %q", secret)
		}
	}
	got := verify(t, res, env)
	if got.Exit != ExitConforms || !got.Report.Conforms || len(got.Report.Incomplete) != 0 || len(got.Report.Failures) != 0 {
		t.Fatalf("exit %d (%s), failures %+v, incomplete %v", got.Exit, got.Message, got.Report.Failures, got.Report.Incomplete)
	}
	c := got.Report.Classes[ClassIssuance]
	if c.Passed != len(checksOf(ClassIssuance)) || c.Skipped != 0 || !c.Conforms {
		t.Errorf("issuance %+v", c)
	}
	if got.Report.Date != res.Report.Date || got.Report.CTVerified == "" || got.Report.Installations != res.Report.Installations {
		t.Errorf("date %q, verified %q, installations %+v", got.Report.Date, got.Report.CTVerified, got.Report.Installations)
	}
	if again := verify(t, res, env); again.Exit != ExitConforms {
		t.Errorf("a second -ct-verify: exit %d", again.Exit)
	}
}

// TestEachBrokenLogFailsExactlyItsCheck: a log that does not include the certificate, a tree
// head the log did not sign, and a certificate for the name that someone else obtained.
func TestEachBrokenLogFailsExactlyItsCheck(t *testing.T) {
	for name, tt := range map[string]struct {
		fault refca.Fault
		want  string
	}{
		"I7 not included":         {refca.NotIncluded, CheckIssuanceInclusion},
		"I9 an extra certificate": {refca.ExtraCertificate, CheckIssuanceSnapshot},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res, env := issuanceRun(t, refop.Config{CAFaults: tt.fault})
			got := verify(t, res, env)
			if f := failures(got); !slices.Equal(f, []string{"live:" + tt.want}) || got.Exit != ExitFails {
				t.Errorf("exit %d, failed %v, want %s", got.Exit, f, tt.want)
			}
		})
	}
}

// TestATreeHeadThatDoesNotVerifyDecidesNothing: a log whose tree head does not verify with the
// key of the list (I8) leaves the inclusion open; it says nothing about the operator.
func TestATreeHeadThatDoesNotVerifyDecidesNothing(t *testing.T) {
	res, env := issuanceRun(t, refop.Config{CAFaults: refca.BadTreeHead})
	got := verify(t, res, env)
	if got.Exit != ExitIncomplete || len(got.Report.Failures) != 0 || !strings.Contains(got.Message, "again") ||
		!strings.Contains(strings.Join(got.Report.Incomplete, "|"), "tree head that verifies") {
		t.Errorf("exit %d (%s), failures %+v, incomplete %v", got.Exit, got.Message, got.Report.Failures, got.Report.Incomplete)
	}
}

// TestBeforeTheMergeDelayTheRunWaits: a log that has not included the certificate before its
// maximum merge delay makes the result incomplete, with the time to try again.
func TestBeforeTheMergeDelayTheRunWaits(t *testing.T) {
	res, env := issuanceRun(t, refop.Config{CAFaults: refca.NotIncluded})
	list := env.LogList
	env.LogList = func(ctx context.Context) (*ctlog.List, error) {
		l, err := list(ctx)
		if err == nil {
			l.Operators[0].Logs[0].MMD = 3600
		}
		return l, err
	}
	got := verify(t, res, env)
	c := got.Report.Classes[ClassIssuance]
	if got.Exit != ExitIncomplete || len(got.Report.Failures) != 0 || c.Skipped != 1 ||
		!strings.Contains(strings.Join(got.Report.Incomplete, "|"), "-ct-verify again") {
		t.Errorf("exit %d, failures %+v, issuance %+v, incomplete %v", got.Exit, got.Report.Failures, c, got.Report.Incomplete)
	}
}

// TestASnapshotNeedsBothSources: a source that does not answer leaves the snapshot open.
func TestASnapshotNeedsBothSources(t *testing.T) {
	for name, change := range map[string]func(*Env){
		"Cert Spotter": func(e *Env) { e.Sources.CertSpotter = "https://" + closedPort(t) },
		"crt.sh":       func(e *Env) { e.Sources.CrtSh = "https://" + closedPort(t) + "/" },
		"no sources":   func(e *Env) { e.Sources = CTSources{} },
		"not a list":   func(e *Env) { e.Sources.CrtSh = e.Sources.CertSpotter + "/v1/nothing" },
	} {
		t.Run(name, func(t *testing.T) {
			res, env := issuanceRun(t, refop.Config{})
			change(&env)
			got := verify(t, res, env)
			c := got.Report.Classes[ClassIssuance]
			if got.Exit != ExitIncomplete || len(got.Report.Failures) != 0 || c.Skipped != 1 || c.Passed != 5 ||
				!strings.Contains(strings.Join(got.Report.Incomplete, "|"), "snapshot") {
				t.Errorf("exit %d, issuance %+v, incomplete %v", got.Exit, c, got.Report.Incomplete)
			}
		})
	}
}

// TestCTVerifyRefusesWhatIsNoFileOfARun: settings and files that -ct-verify cannot use.
func TestCTVerifyRefusesWhatIsNoFileOfARun(t *testing.T) {
	res, env := issuanceRun(t, refop.Config{})
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	raw := must(os.ReadFile(res.CTFile))
	var file map[string]any
	must0(json.Unmarshal(raw, &file))
	file["version"] = 2
	for name, path := range map[string]string{
		"missing":       filepath.Join(dir, "none.ct.json"),
		"garbage":       write("garbage.ct.json", "nope"),
		"other version": write("v2.ct.json", string(must(json.Marshal(file)))),
		"no checks due": write("done.ct.json", strings.Replace(string(raw), `"skipped": 2`, `"skipped": 0`, 1)),
	} {
		got := CTVerifyWith(ctx(t), Settings{CTVerifyPath: path}, env)
		if got.Exit != ExitUsage || got.Message == "" {
			t.Errorf("%s: exit %d (%s)", name, got.Exit, got.Message)
		}
	}
	for name, s := range map[string]Settings{
		"with an operator": {CTVerifyPath: res.CTFile, Operator: "op.example.net"},
		"with a clean-up":  {CTVerifyPath: res.CTFile, CleanupPath: "x"},
		"with production":  {CTVerifyPath: res.CTFile, ACMEProduction: true},
	} {
		if got := CTVerifyWith(ctx(t), s, env); got.Exit != ExitUsage {
			t.Errorf("%s: exit %d", name, got.Exit)
		}
	}
	if got := RunWith(ctx(t), Settings{CTVerifyPath: res.CTFile}, env); got.Exit != ExitUsage {
		t.Errorf("a run with -ct-verify: exit %d", got.Exit)
	}
}

// TestOnlyAProductionRunThatObtainedACertificateWritesAFile: staging, or no certificate, gives
// no file for -ct-verify.
func TestOnlyAProductionRunThatObtainedACertificateWritesAFile(t *testing.T) {
	for name, tt := range map[string]struct {
		production bool
		cfg        refop.Config
	}{
		"staging":        {false, refop.Config{}},
		"no certificate": {true, refop.Config{Faults: refop.CASeesNoChallenge}},
	} {
		t.Run(name, func(t *testing.T) {
			r, env := serve(t, tt.cfg)
			s := enrollSettings(t, r, ClassIssuance)
			s.ACMEProduction = tt.production
			res := RunWith(ctx(t), s, env)
			if res.CTFile != "" || strings.Contains(res.Message, "-ct-verify") {
				t.Errorf("file %q, message %q", res.CTFile, res.Message)
			}
			if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(s.StatePath), "*.ct.json")); len(matches) != 0 {
				t.Errorf("files %v", matches)
			}
		})
	}
}

// TestInclusionWithoutAUsableList: without the log list, or with a list that has none of the
// logs of the SCTs, the inclusion is left open.
func TestInclusionWithoutAUsableList(t *testing.T) {
	for name, tt := range map[string]struct {
		list func(context.Context) (*ctlog.List, error)
		want string
	}{
		"no list": {func(context.Context) (*ctlog.List, error) { return nil, ctlog.ErrList }, "log list could not be fetched"},
		"no log of ours": {func(context.Context) (*ctlog.List, error) {
			return reflog.List(reflog.New("https://ct.example.com/o/", false))
		}, "no SCT"},
	} {
		t.Run(name, func(t *testing.T) {
			res, env := issuanceRun(t, refop.Config{})
			env.LogList = tt.list
			got := verify(t, res, env)
			if got.Exit != ExitIncomplete || len(got.Report.Failures) != 0 || !strings.Contains(strings.Join(got.Report.Incomplete, "|"), tt.want) {
				t.Errorf("exit %d, failures %+v, incomplete %v", got.Exit, got.Report.Failures, got.Report.Incomplete)
			}
		})
	}
}

// TestAFileOfAnEarlierRunIsReplaced: a file or link at the path is removed, and the new file is
// the owner's alone.
func TestAFileOfAnEarlierRunIsReplaced(t *testing.T) {
	r, env := serve(t, refop.Config{})
	s := enrollSettings(t, r, ClassIssuance)
	target := filepath.Join(t.TempDir(), "elsewhere")
	must0(os.WriteFile(target, []byte("keep"), 0o644))
	must0(os.Symlink(target, ctPath(s.StatePath)))
	res := RunWith(ctx(t), s, env)
	info, err := os.Lstat(res.CTFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, info)
	}
	if data := must(os.ReadFile(target)); string(data) != "keep" {
		t.Error("the target of the link was written")
	}
}
