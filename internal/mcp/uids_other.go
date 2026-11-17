//go:build !linux && !darwin

package mcp

import "errors"

func processUIDs(int) ([]uint32, error) {
	return nil, errors.New("reading a process's uids is not supported on this platform")
}
