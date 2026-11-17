// Package version holds build metadata for DBGuard binaries.
package version

import "runtime"

// Populated at build time via -ldflags -X.
var (
	Version = "dev"
	Commit  = "none"
)

// String renders the short version line used by `dbguard-cli version`.
func String() string {
	return "dbguard " + Version + " (commit " + Commit + ", " + runtime.GOOS + "/" + runtime.GOARCH + ", " + runtime.Version() + ")"
}
