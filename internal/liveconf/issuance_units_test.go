// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
)

// judged runs one judgement on a fresh script and returns the failure and the incomplete texts.
func judged(judge func(*issuing)) (string, string, int) {
	r := newRun(Settings{Classes: AllClasses, Version: "test"}, Env{})
	is := &issuing{s: &script{r: r, seen: map[string]bool{}}, name: "h.homes.example.org"}
	judge(is)
	failure := ""
	if len(r.rep.Failures) > 0 {
		failure = r.rep.Failures[0].Got
	}
	return failure, strings.Join(r.rep.Incomplete, "|"), r.rep.Classes[ClassIssuance].Passed
}

func TestJudgeIssueTellsTheOperatorFromTheCA(t *testing.T) {
	for name, tt := range map[string]struct {
		o          outcome
		failure    string
		incomplete string
	}{
		"unreachable":       {outcome{unreachable: kindTimeout}, "", "cannot be reached"},
		"garbage":           {outcome{chain: [][]byte{{1}}}, "cannot be parsed", ""},
		"caa":               {outcome{problem: "caa"}, "CAA records it sees", ""},
		"unauthorized":      {outcome{problem: "unauthorized"}, "did not find the challenge value", ""},
		"incorrectResponse": {outcome{problem: "incorrectResponse"}, "did not find the challenge value", ""},
		"challenge refused": {outcome{problem: problemChallengeRefused}, "refused the challenge value", ""},
		"not visible":       {outcome{problem: problemNotVisible}, "did not show", ""},
		"rate limited":      {outcome{problem: "rateLimited"}, "", "could not be judged"},
		"operator error":    {outcome{problem: "operator-server-internal"}, "", "could not be judged"},
	} {
		failure, incomplete, _ := judged(func(is *issuing) { is.judgeIssue(tt.o) })
		if !strings.Contains(failure, tt.failure) || (tt.failure == "") != (failure == "") || !strings.Contains(incomplete, tt.incomplete) {
			t.Errorf("%s: failure %q, incomplete %q", name, failure, incomplete)
		}
	}
}

func TestJudgeRefusalCountsOnlyCAA(t *testing.T) {
	for name, tt := range map[string]struct {
		o          outcome
		failure    bool
		passed     int
		incomplete string
	}{
		"issued":      {outcome{chain: [][]byte{{1}}}, true, 0, ""},
		"caa":         {outcome{problem: "caa"}, false, 1, ""},
		"unreachable": {outcome{unreachable: kindOther}, false, 0, "cannot be reached"},
		"other":       {outcome{problem: "unauthorized"}, false, 0, "another reason than CAA"},
	} {
		failure, incomplete, passed := judged(func(is *issuing) { is.judgeRefusal(CheckIssuanceForeign, "an order", tt.o) })
		if (failure != "") != tt.failure || passed != tt.passed || !strings.Contains(incomplete, tt.incomplete) {
			t.Errorf("%s: failure %q, passed %d, incomplete %q", name, failure, passed, incomplete)
		}
	}
}

func TestFailedReadsTheProblemTypeOnly(t *testing.T) {
	caa := &acme.Error{ProblemType: problemPrefix + "caa", Detail: "anything the CA says"}
	for name, tt := range map[string]struct {
		err  error
		want outcome
	}{
		"authorization":          {&acme.AuthorizationError{Errors: []error{errors.New("x"), caa}}, outcome{problem: "caa"}},
		"authorization, no type": {&acme.AuthorizationError{}, outcome{problem: "invalid-authorization"}},
		"problem":                {caa, outcome{problem: "caa"}},
		"order":                  {&acme.OrderError{}, outcome{problem: "invalid-order"}},
		"network":                {errors.New("dial"), outcome{unreachable: kindOther}},
	} {
		if got := failed(tt.err); got.problem != tt.want.problem || got.unreachable != tt.want.unreachable {
			t.Errorf("%s: %+v", name, got)
		}
	}
	for in, want := range map[string]string{
		problemPrefix + "badNonce":              "badNonce",
		"urn:other:caa":                         "other",
		problemPrefix:                           "other",
		problemPrefix + "a-b":                   "other",
		problemPrefix + strings.Repeat("a", 41): "other",
	} {
		if got := problemName(in); got != want {
			t.Errorf("problemName(%q) = %q", in, got)
		}
	}
}
