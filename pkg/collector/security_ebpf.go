//go:build linux && ebpf

package collector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/symbol"
)

// SecurityEBPFCollector consumes the eBPF security ring buffer (#59) and
// publishes one SecurityEvent per runtime PROT_EXEC mapping (mmap/mprotect) or
// SELinux AVC denial observed for the target. For exec-map events it resolves
// the originating application call site inline (events are low-rate, so no lazy
// ResolveStack RPC is needed). eBPF-only — no /proc fallback, never simulated.
type SecurityEBPFCollector struct {
	tracer *bpf.SecurityTracer
	sym    *symbol.Symbolizer // nil if /proc maps couldn't be parsed
	ch     chan interface{}
	stop   chan struct{}

	mu        sync.Mutex
	siteCache map[int32]secSite // stack_id → resolved app call site
}

// secSite is the resolved application call site for a stack_id: the raw frame
// address plus its symbolization. Cached (stacks are stable per process life).
type secSite struct {
	addr  uint64
	frame symbol.Frame
}

func NewSecurityEBPFCollector() *SecurityEBPFCollector {
	return &SecurityEBPFCollector{
		ch:        make(chan interface{}, 64),
		stop:      make(chan struct{}),
		siteCache: make(map[int32]secSite),
	}
}

func (c *SecurityEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenSecurityTracer(pid)
	if err != nil {
		return fmt.Errorf("security eBPF: %w", err)
	}
	c.tracer = tracer
	// Symbolize call sites best-effort: without /proc maps the sites degrade to
	// hex — never fail Start over it (same as the heap collector).
	if sym, err := symbol.NewSymbolizer(pid); err == nil {
		c.sym = sym
	} else {
		fmt.Fprintf(os.Stderr, "security: call-site symbolization unavailable for pid %d: %v\n", pid, err)
	}
	go c.readLoop(tracer)
	return nil
}

func (c *SecurityEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *SecurityEBPFCollector) Subscribe() <-chan interface{} { return c.ch }

// readLoop drains the security ring buffer, decoding each record and (for
// exec-map) resolving its call site, then publishing non-blocking. Exits on
// io.EOF (tracer closed); a garbled record is skipped, keeping the stream alive.
func (c *SecurityEBPFCollector) readLoop(tracer *bpf.SecurityTracer) {
	if tracer == nil {
		return
	}
	for {
		rec, err := tracer.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		ev := c.decode(time.Now(), rec)
		select {
		case c.ch <- ev:
		default:
		}
	}
}

// decode turns a raw record into a SecurityEvent, resolving the exec-map call
// site inline.
func (c *SecurityEBPFCollector) decode(ts time.Time, rec bpf.SecurityRecord) SecurityEvent {
	if rec.Kind == secKindLSM {
		return decodeSecurityLSM(ts, rec.LsmRequested, rec.LsmDenied, rec.LsmAudited)
	}
	ev := decodeSecurityExecMap(ts, rec.Op, rec.Prot, rec.Flags, rec.Addr, rec.Len)
	addr, frame := c.resolveSite(rec.StackID)
	ev.CallSite = addr
	ev.AddrHex = securityAddrHex(addr)
	ev.Func = frame.Func
	ev.File = frame.File
	ev.Line = frame.Line
	ev.Module = frame.Module
	ev.Offset = frame.Offset
	return ev
}

// resolveSite maps a stack_id to the application call site that triggered the
// mapping — the first frame outside libc/ld (the leaf is the libc mmap wrapper).
// Cached under c.mu. Returns (0, zero) when the stack walk failed.
func (c *SecurityEBPFCollector) resolveSite(stackID int32) (uint64, symbol.Frame) {
	if stackID < 0 || c.tracer == nil {
		return 0, symbol.Frame{}
	}
	c.mu.Lock()
	if s, ok := c.siteCache[stackID]; ok {
		c.mu.Unlock()
		return s.addr, s.frame
	}
	c.mu.Unlock()

	frames, err := c.tracer.ResolveStack(stackID)
	if err != nil || len(frames) == 0 {
		return 0, symbol.Frame{}
	}

	var site secSite
	if c.sym != nil {
		for _, f := range frames {
			if f == 0 {
				continue
			}
			fr := c.sym.Symbolize(f)
			if !isLoaderModule(fr.Module) {
				site = secSite{addr: f, frame: fr}
				break
			}
		}
		if site.addr == 0 { // every frame was loader/libc — fall back to the leaf
			site = secSite{addr: frames[0], frame: c.sym.Symbolize(frames[0])}
		}
	} else {
		site = secSite{addr: frames[0]}
	}

	c.mu.Lock()
	c.siteCache[stackID] = site
	c.mu.Unlock()
	return site.addr, site.frame
}
