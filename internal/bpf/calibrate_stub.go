//go:build !linux || !ebpf

package bpf

import "errors"

// UprobeTrapCost: see calibrate.go.
type UprobeTrapCost struct {
	EntryNs  float64
	ReturnNs float64
	Calls    int
}

func CalibrateUprobeTraps() (UprobeTrapCost, error) {
	return UprobeTrapCost{}, errors.New("uprobe calibration needs the eBPF build")
}
