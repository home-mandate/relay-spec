// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"runtime/debug"
	"testing"
)

func TestBuildVersion(t *testing.T) {
	read := func(v string, ok bool) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: v}}, ok }
	}
	for name, tt := range map[string]struct {
		ldflags string
		read    func() (*debug.BuildInfo, bool)
		want    string
	}{
		"ldflags win":       {"1.2.3", read("v9.0.0", true), "1.2.3"},
		"ldflags with v":    {"v0.1.0", read("v9.0.0", true), "0.1.0"},
		"module version":    {"", read("v0.1.0", true), "0.1.0"},
		"release candidate": {"", read("v0.1.0-rc.1", true), "0.1.0-rc.1"},
		"pseudo-version":    {"", read("v0.1.1-0.20261126120000-abcdef123456", true), "0.1.1-0.20261126120000-abcdef123456"},
		"devel build":       {"", read("(devel)", true), "devel"},
		"empty version":     {"", read("", true), "devel"},
		"no build info":     {"", read("v0.1.0", false), "devel"},
		"nil build info":    {"", func() (*debug.BuildInfo, bool) { return nil, true }, "devel"},
	} {
		if got := BuildVersion(tt.ldflags, tt.read); got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}
