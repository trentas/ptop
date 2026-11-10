//go:build !linux && !darwin

package serve

// targetExe has no source for the executable on this platform.
func targetExe(int) string { return "" }
