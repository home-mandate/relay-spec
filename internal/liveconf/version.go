// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"runtime/debug"
	"strings"
)

// develVersion is the version of a build that names none.
const develVersion = "devel"

// BuildVersion returns the version of a command for its report: the one set at build time,
// else the module version of the build (go install ...@vX.Y.Z), else "devel". Either loses a
// leading "v", so that every build names a release as the release workflow does ("0.1.0").
func BuildVersion(ldflags string, read func() (*debug.BuildInfo, bool)) string {
	if ldflags != "" {
		return strings.TrimPrefix(ldflags, "v")
	}
	info, ok := read()
	if !ok || info == nil || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return develVersion
	}
	return strings.TrimPrefix(info.Main.Version, "v")
}
