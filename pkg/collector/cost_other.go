//go:build !linux

package collector

import "time"

func processCPU(int) (time.Duration, bool) { return 0, false }
