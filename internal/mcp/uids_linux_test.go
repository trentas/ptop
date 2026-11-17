//go:build linux

package mcp

import (
	"slices"
	"testing"
)

func TestParseStatusUIDs(t *testing.T) {
	const status = "Name:\tsudo\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n"
	got, err := parseStatusUIDs(status)
	if err != nil || !slices.Equal(got, []uint32{1000, 0, 0, 0}) {
		t.Errorf("= %v, %v; want [1000 0 0 0]", got, err)
	}
	for _, bad := range []string{"Name:\tx\n", "Uid:\t1000\t0\n", "Uid:\ta\tb\tc\td\n"} {
		if _, err := parseStatusUIDs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
