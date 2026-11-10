package serve

import (
	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// The host context in the handshake and in HostSample (#153). Both render to
// nil when nothing was read, so a consumer sees the field absent (unknown)
// rather than present and empty.

var virtStates = map[collector.Virtualization]pb.Virtualization_State{
	collector.VirtUnknown:     pb.Virtualization_STATE_UNSPECIFIED,
	collector.VirtBareMetal:   pb.Virtualization_STATE_BARE_METAL,
	collector.VirtVirtualized: pb.Virtualization_STATE_VIRTUALIZED,
}

func hostWire(h collector.HostInfo) *pb.HostInfo {
	if h.IsZero() {
		return nil
	}
	out := &pb.HostInfo{
		KernelRelease:  h.KernelRelease,
		Machine:        h.Machine,
		Virtualization: &pb.Virtualization{State: virtStates[h.Virt], Hypervisor: h.Hypervisor},
		DmiVendor:      h.DMIVendor,
		DmiProduct:     h.DMIProduct,
	}
	if !h.CPU.IsZero() {
		c := h.CPU
		out.Cpu = &pb.HostCpu{
			Vendor: c.Vendor, ModelName: c.ModelName, Family: c.Family, Model: c.Model,
			Stepping: c.Stepping, Variant: c.Variant, Microcode: c.Microcode,
			LogicalCpus: uint32(c.LogicalCPUs), Smt: c.SMT,
		}
		for _, ct := range c.CoreTypes {
			out.Cpu.CoreTypes = append(out.Cpu.CoreTypes, &pb.CoreType{Name: ct.Name, Cpus: uint32(ct.CPUs)})
		}
	}
	return out
}

func limitsWire(l collector.CgroupLimits) *pb.CgroupLimits {
	if l == (collector.CgroupLimits{}) {
		return nil
	}
	return &pb.CgroupLimits{
		Cgroup: l.Cgroup, CpuMax: l.CPUMax, CpuWeight: l.CPUWeight,
		MemoryMax: l.MemoryMax, CpusetCpusEffective: l.CpusetCPUsEffective,
	}
}

// targetLimits reads the target cgroup's limits now: the process's current
// cgroup in pid mode, the target cgroup in cgroup mode.
func targetLimits(t Target) *pb.CgroupLimits {
	cg := ""
	switch {
	case t.IsCgroup():
		cg = collector.CgroupBelowRoot(t.CgroupPath)
	case t.PID > 0:
		cg, _ = collector.CgroupOf(t.PID)
	}
	if cg == "" {
		return nil
	}
	return limitsWire(collector.ReadCgroupLimits(cg))
}

func throttlingWire(t *collector.CPUThrottling) *pb.CpuThrottling {
	if t == nil {
		return nil
	}
	return &pb.CpuThrottling{NrPeriods: t.NrPeriods, NrThrottled: t.NrThrottled, ThrottledUsec: t.ThrottledUsec}
}

// pressureWire renders the PSI of the three resources, nil when none was read.
func pressureWire(p collector.CgroupPressure) *pb.CgroupPressure {
	if p.CPU == nil && p.Memory == nil && p.IO == nil {
		return nil
	}
	return &pb.CgroupPressure{Cpu: oneWire(p.CPU), Memory: oneWire(p.Memory), Io: oneWire(p.IO)}
}

func oneWire(p *collector.Pressure) *pb.Pressure {
	if p == nil {
		return nil
	}
	out := &pb.Pressure{Some: stallWire(p.Some)}
	if p.Full != nil {
		out.Full = stallWire(*p.Full)
	}
	return out
}

func stallWire(s collector.PressureStall) *pb.PressureStall {
	return &pb.PressureStall{Avg10: s.Avg10, Avg60: s.Avg60, Avg300: s.Avg300, TotalUsec: s.TotalUsec}
}
