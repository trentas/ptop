//go:build linux && ebpf

package bpf

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed programs/signal.bpf.o
var signalBPFObj []byte

// SignalRecord is the 1:1 layout of struct sig_event in programs/signal.bpf.c
// (#58). Fixed size 56 bytes; binary.LittleEndian parses it directly from the
// ring buffer. SenderTID/Err/Group are carried for layout + completeness; the
// collector surfaces the rest.
type SignalRecord struct {
	TsNs       uint64
	Signo      uint32
	SenderPID  uint32
	SenderTID  uint32
	TargetTID  uint32
	Code       int32
	Err        int32
	Result     uint32
	Group      uint32
	SenderComm [16]byte
}

// SignalTracer loads signal.bpf.o, attaches the signal:signal_generate
// tracepoint filtered to the target's global pid, and exposes Next() to deliver
// parsed records.
type SignalTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader
}

func OpenSignalTracer(pid int) (*SignalTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(signalBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse signal BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load signal collection: %w", err)
	}
	t := &SignalTracer{coll: coll}

	// The signal_generate tracepoint reports the receiver by its global (init-ns)
	// pid, and we can't project the (non-current) target via the ns helper — so
	// filter against the resolved global pid.
	targetMap := coll.Maps["sig_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("sig_target_pid map missing")
	}
	var key uint32
	gpid := uint32(globalPID(pid))
	if err := targetMap.Update(&key, &gpid, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set sig_target_pid: %w", err)
	}

	prog := coll.Programs["handle_signal_generate"]
	if prog == nil {
		t.Close()
		return nil, errors.New("handle_signal_generate program missing")
	}
	l, err := link.Tracepoint("signal", "signal_generate", prog, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach signal/signal_generate: %w", err)
	}
	t.links = append(t.links, l)

	evMap := coll.Maps["sig_events"]
	if evMap == nil {
		t.Close()
		return nil, errors.New("sig_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(evMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("signal ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// globalPID resolves pid's PID as seen in the INITIAL (global) namespace, read
// from the NSpid line of /proc/<pid>/status (the first field is the outermost
// namespace). On a normal host the ns-local pid and the global pid are identical
// and NSpid has a single entry; under a nested pid namespace they differ and the
// global one is what the signal_generate tracepoint reports. Falls back to pid
// when status is unreadable or NSpid is absent (older kernels).
func globalPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return pid
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		rest, ok := strings.CutPrefix(line, "NSpid:")
		if !ok {
			continue
		}
		if f := strings.Fields(rest); len(f) > 0 {
			if v, err := strconv.Atoi(f[0]); err == nil {
				return v
			}
		}
		break
	}
	return pid
}

// Next blocks until the next signal record arrives. Returns io.EOF once the
// tracer is closed. A short/garbled record is reported as an error but does not
// close the stream — the caller keeps reading.
func (t *SignalTracer) Next() (SignalRecord, error) {
	var rec SignalRecord
	if t == nil || t.rb == nil {
		return rec, errors.New("tracer not initialized")
	}
	r, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return rec, io.EOF
		}
		return rec, err
	}
	if len(r.RawSample) < 56 {
		return rec, fmt.Errorf("short signal event: %d bytes", len(r.RawSample))
	}
	if err := binary.Read(bytes.NewReader(r.RawSample), binary.LittleEndian, &rec); err != nil {
		return rec, fmt.Errorf("decode signal event: %w", err)
	}
	return rec, nil
}

func (t *SignalTracer) Close() error {
	if t == nil {
		return nil
	}
	// Close the reader first so a blocked Next unblocks with io.EOF.
	if t.rb != nil {
		_ = t.rb.Close()
		t.rb = nil
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
	}
	return nil
}
