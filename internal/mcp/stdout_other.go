//go:build !linux && !darwin

package mcp

import "os"

// TakeStdout cannot move descriptors here, so the protocol shares stdout with
// whatever else writes to it.
func TakeStdout() (*os.File, error) { return os.Stdout, nil }
