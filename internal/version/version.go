// SPDX-License-Identifier: Apache-2.0

// Package version holds the build version, set via -ldflags.
package version

// Version follows semantic versioning; overridden at build time with
// -ldflags "-X github.com/tsuzu/xdpl2/internal/version.Version=v0.1.0".
var Version = "v0.1.0-dev"
