package bpf

import (
	"reflect"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"0-3", []int{0, 1, 2, 3}},
		{"0-3\n", []int{0, 1, 2, 3}},
		{"0", []int{0}},
		{"0,2-3,7", []int{0, 2, 3, 7}},
		{"2-2", []int{2}},
		// A hot-unplugged machine leaves gaps: the ids matter, not the count.
		{"0-1,4-5", []int{0, 1, 4, 5}},
		{"", nil},
		{"\n", nil},
	}
	for _, tc := range cases {
		got, err := parseCPUList(tc.in)
		if err != nil {
			t.Errorf("parseCPUList(%q): %v", tc.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseCPUList(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseCPUListRejectsGarbage(t *testing.T) {
	for _, in := range []string{"x", "1-", "-1", "3-1", "0,x", "1.5"} {
		if _, err := parseCPUList(in); err == nil {
			t.Errorf("parseCPUList(%q) = nil error, want a failure", in)
		}
	}
}
