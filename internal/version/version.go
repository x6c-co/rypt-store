// Package version reports the build version, set at link time with
// -ldflags "-X github.com/x6c-co/rypt-store/internal/version.Version=v1.2.3".
package version

import "runtime/debug"

// Version is the release version, or "dev".
var Version = "dev"

// String returns the version with the VCS revision when known.
func String() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return "dev-" + s.Value[:12]
			}
		}
	}
	return Version
}
