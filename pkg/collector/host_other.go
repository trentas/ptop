//go:build !linux

package collector

import "errors"

var errHostUnsupported = errors.New("host context needs /proc and /sys")

// ReadHostInfo has nothing to read outside Linux.
func ReadHostInfo() HostInfo { return HostInfo{} }

func CgroupOf(int) (string, error) { return "", errHostUnsupported }

func ReadCgroupLimits(string) CgroupLimits { return CgroupLimits{} }

type HostCollector struct{}

func NewHostCollector() *HostCollector               { return &HostCollector{} }
func (*HostCollector) Start(int) error               { return errHostUnsupported }
func (*HostCollector) StartCgroup(string) error      { return errHostUnsupported }
func (*HostCollector) Stop()                         {}
func (*HostCollector) Subscribe() <-chan interface{} { return nil }
