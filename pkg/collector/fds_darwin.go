//go:build darwin

package collector

import (
	"fmt"
	"sync"
	"time"
)

// FDCollector enumerates per-process FDs on macOS via libproc.
//
// Linux parity: same three message types as the /proc collector — full
// []FDEntry snapshots every 500ms, plus FDEvent + TimelineEvent for opens,
// closes and dup2-style reuses detected by polling. Internal layout mirrors
// the Linux baseline-map approach so the F6 view sees identical message
// shapes regardless of OS.
//
// Differences vs Linux:
//   - PosKnown is always false, so Active and Bytes are not readings and
//     F6 shows them as unmeasured: libproc has no per-FD "pos" cursor like
//     /proc/<pid>/fdinfo/pos to detect activity between polls.
//   - Bytes is 0: there's no cumulative file-position equivalent on
//     macOS, and sockets are no exception — socket_info exposes only the
//     current send/recv buffer occupancy (sbi_cc), not lifetime byte
//     totals, so there's nothing cumulative to put here. The F3 view does
//     surface that occupancy as a backlog gauge (NetConn.Tx/RxBytes); the
//     F6 Bytes column stays 0 to avoid mixing a gauge into a counter slot.
//   - No FDLimit: macOS has no public API that reads another process's
//     RLIMIT_NOFILE (getrlimit is self-only, and libproc does not carry it),
//     so the limit stays unknown and F6 raises no "close to the limit" alert.

type FDCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	baseline map[int32]fdStateDarwin
	primed   bool // the first poll has been taken
}

type fdStateDarwin struct {
	openedAt    time.Time
	desc        string
	fdType      string
	preexisting bool // open at the first poll, so openedAt is when ptop saw it
}

func NewFDCollector() *FDCollector {
	return &FDCollector{
		ch:       make(chan interface{}, 128),
		stop:     make(chan struct{}),
		baseline: make(map[int32]fdStateDarwin),
	}
}

func (c *FDCollector) Start(pid int) error {
	c.pid = pid
	if _, err := ListFDs(pid); err != nil {
		return fmt.Errorf("FD collector unavailable for pid %d: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *FDCollector) Stop()                          { close(c.stop) }
func (c *FDCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *FDCollector) loop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	c.collectAndEmit() // first snapshot immediately so the UI has data
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.collectAndEmit()
		}
	}
}

func (c *FDCollector) collectAndEmit() {
	fds, events, err := c.collect()
	if err != nil {
		return
	}
	for _, e := range events {
		c.emit(e)
	}
	c.emit(fds)
}

func (c *FDCollector) emit(msg interface{}) {
	publish(c.ch, msg)
}

func (c *FDCollector) collect() ([]FDEntry, []interface{}, error) {
	rawFDs, err := ListFDs(c.pid)
	if err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	// The first poll is the baseline: its fds were open before ptop looked, so
	// it emits no "openat" for them, as on Linux.
	first := !c.primed
	c.primed = true
	seen := make(map[int32]bool, len(rawFDs))
	result := make([]FDEntry, 0, len(rawFDs))
	events := make([]interface{}, 0)

	for _, raw := range rawFDs {
		seen[raw.FD] = true
		desc, fdType, flags := c.describe(raw)

		prev, hadPrev := c.baseline[raw.FD]
		if !hadPrev {
			c.baseline[raw.FD] = fdStateDarwin{openedAt: now, desc: desc, fdType: fdType, preexisting: first}
			prev = c.baseline[raw.FD]
			if !first {
				events = append(events,
					FDEvent{Timestamp: now, Message: fmt.Sprintf("openat fd=%d %s", raw.FD, desc)},
					TimelineEvent{Timestamp: now, Category: "fd", Message: fmt.Sprintf("openat → fd=%d %s", raw.FD, desc)},
				)
			}
		} else if prev.desc != desc {
			events = append(events,
				FDEvent{Timestamp: now, Message: fmt.Sprintf("reuse fd=%d %s → %s", raw.FD, prev.desc, desc)},
				TimelineEvent{Timestamp: now, Category: "fd", Message: fmt.Sprintf("dup/reuse fd=%d → %s", raw.FD, desc)},
			)
			c.baseline[raw.FD] = fdStateDarwin{openedAt: now, desc: desc, fdType: fdType}
			prev = c.baseline[raw.FD]
		}

		// No offset to read (see the file header), so PosKnown stays false
		// and Bytes and Active are not readings.
		result = append(result, FDEntry{
			FD:          int(raw.FD),
			Type:        fdType,
			Desc:        desc,
			Flags:       flags,
			AgeMs:       now.Sub(prev.openedAt).Milliseconds(),
			Preexisting: prev.preexisting,
		})
	}

	// Detect closes — FDs in baseline that didn't appear in this listing.
	for fd, prev := range c.baseline {
		if !seen[fd] {
			events = append(events,
				FDEvent{Timestamp: now, Message: fmt.Sprintf("close fd=%d %s", fd, prev.desc)},
				TimelineEvent{Timestamp: now, Category: "fd", Message: fmt.Sprintf("close fd=%d %s", fd, prev.desc)},
			)
			delete(c.baseline, fd)
		}
	}

	return result, events, nil
}

// describe resolves a raw FD into (description, type-label, flags) tuple.
// type-label matches the Linux strings so the F6 view filters work
// unchanged ("file", "socket", "pipe", "epoll", "event", "timer").
func (c *FDCollector) describe(raw LPFDInfo) (desc, fdType, flags string) {
	switch raw.Type {
	case FDTypeVNode:
		v, err := FDVNodePath(c.pid, raw.FD)
		if err != nil {
			return "(unknown file)", "file", ""
		}
		return v.Path, "file", ""
	case FDTypeSocket:
		s, err := FDSocketInfo(c.pid, raw.FD)
		if err != nil {
			return "(unknown socket)", "socket", ""
		}
		return formatSocket(s), "socket", ""
	case FDTypePipe:
		p, err := FDPipeInfo(c.pid, raw.FD)
		if err != nil {
			return "pipe", "pipe", ""
		}
		return fmt.Sprintf("pipe:%x", p.PipeID), "pipe", ""
	case FDTypeKQueue:
		// Closest match to Linux epoll for filter/UI purposes — both are
		// the OS's "watch a set of FDs for readiness" primitive.
		return "kqueue", "epoll", ""
	case FDTypePSHM:
		return "posix-shm", "file", ""
	case FDTypePSEM:
		return "posix-sem", "file", ""
	case FDTypeFSEvents:
		return "fsevents", "event", ""
	default:
		return fmt.Sprintf("type=%d", raw.Type), "other", ""
	}
}

// formatSocket renders an LPSocketFDInfo into a human-readable string
// matching the F3/F6 panels' expectations.
func formatSocket(s LPSocketFDInfo) string {
	switch s.Family {
	case 2: // AF_INET
		proto := "UDP"
		if s.SockType == 1 { // SOCK_STREAM
			proto = "TCP"
		}
		if s.RemoteAddr == "" || s.RemoteAddr == "0.0.0.0:0" {
			return fmt.Sprintf("%s listen %s", proto, s.LocalAddr)
		}
		return fmt.Sprintf("%s %s↔%s", proto, s.LocalAddr, s.RemoteAddr)
	case 30: // AF_INET6
		proto := "UDP6"
		if s.SockType == 1 {
			proto = "TCP6"
		}
		if s.RemoteAddr == "" {
			return fmt.Sprintf("%s listen %s", proto, s.LocalAddr)
		}
		return fmt.Sprintf("%s %s↔%s", proto, s.LocalAddr, s.RemoteAddr)
	case 1: // AF_UNIX
		if s.LocalAddr != "" {
			return fmt.Sprintf("UNIX %s", s.LocalAddr)
		}
		return "UNIX (unnamed)"
	default:
		return fmt.Sprintf("socket family=%d", s.Family)
	}
}
