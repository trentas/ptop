//go:build linux

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FDCollector reads /proc/<pid>/fd and /proc/<pid>/fdinfo every 500ms.
// Works without root, without eBPF — first collector implemented.
//
// Publishes four message types on the same channel (consumer does
// type-switch):
//
//   - []FDEntry           — full snapshot of current state (every poll)
//   - FDLimit             — the target's RLIMIT_NOFILE, read from /proc/<pid>/limits
//     every poll (prlimit can change it at runtime); not sent when unreadable
//   - TimelineEvent       — "openat fd=N <desc>" / "close fd=N" event for the global timeline
//   - FDEvent             — compact version dedicated to the F6 ▸ FD Events panel
type FDCollector struct {
	pid      int
	ch       chan interface{}
	stop     chan struct{}
	mu       sync.Mutex
	resolver *SocketResolver

	// state between polls
	baseline map[int]fdState // fd → state at last observation
	primed   bool            // the first poll has been taken
}

type fdState struct {
	openedAt    time.Time
	pos         uint64 // /proc/<pid>/fdinfo/<fd> "pos:" field — used to detect activity
	desc        string // stable description (file path or resolved TCP IP:port)
	fdType      string
	posKnown    bool // the fd has a file offset: a regular file or a block device
	preexisting bool // open at the first poll, so openedAt is when ptop saw it
}

func NewFDCollector() *FDCollector {
	return &FDCollector{
		ch:       make(chan interface{}, 128),
		stop:     make(chan struct{}),
		baseline: make(map[int]fdState),
		resolver: NewSocketResolver(),
	}
}

func (c *FDCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/fd", pid)); err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	// The target's socket tables, not ours: in another network namespace its
	// sockets would never resolve and every one would read "socket:[N]" (#140).
	c.resolver.ForPID(pid)
	go c.loop()
	return nil
}

func (c *FDCollector) Stop() {
	close(c.stop)
}

func (c *FDCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *FDCollector) loop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	// First collection happens immediately so the UI doesn't wait 500ms to show anything
	c.collectAndEmit()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.collectAndEmit()
		}
	}
}

// collectAndEmit takes a snapshot and emits the 3 message types on the
// channel. Events (open/close) are emitted BEFORE the snapshot so the UI
// has the history before re-rendering the table with the new state.
func (c *FDCollector) collectAndEmit() {
	fds, events, err := c.collect()
	if err != nil {
		return
	}
	for _, e := range events {
		c.emit(e)
	}
	// The limit goes before the snapshot, so a consumer never holds a table
	// it would judge against an older limit.
	if lim, ok := readFDLimit(c.pid); ok {
		c.emit(lim)
	}
	c.emit(fds)
}

// readFDLimit reads the target's RLIMIT_NOFILE. /proc/<pid>/limits is
// world-readable, so this needs no privilege the fd listing did not.
func readFDLimit(pid int) (FDLimit, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		return FDLimit{}, false
	}
	return parseFDLimit(string(data))
}

func (c *FDCollector) emit(msg interface{}) {
	// Both classes go out here — an FDEvent per open/close, and the []FDEntry
	// snapshot per poll — so the reserve matters (#121): a process churning
	// descriptors must not cost the consumer its fd table.
	publish(c.ch, msg)
}

// collect returns the current snapshot + events (open/close) detected
// since the last poll.
//
// The first poll is the baseline. Its fds were open before ptop looked, so it
// emits no "openat" for them (they would put opens that never happened on the
// timeline) and marks them Preexisting: their age is a lower bound.
func (c *FDCollector) collect() ([]FDEntry, []interface{}, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", c.pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	first := !c.primed
	c.primed = true
	seen := make(map[int]bool, len(entries))
	result := make([]FDEntry, 0, len(entries))
	events := make([]interface{}, 0)

	for _, e := range entries {
		fdNum, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		seen[fdNum] = true

		fdPath := filepath.Join(fdDir, e.Name())
		link, _ := os.Readlink(fdPath)
		fdType := inferType(link)
		desc := c.describeLink(link)
		flags := readFlags(c.pid, fdNum)
		pos := readFDPos(c.pid, fdNum)

		prev, hadPrev := c.baseline[fdNum]
		// A new life: the fd was not in the baseline, or its description
		// changed (dup2, or a close and an open between two polls).
		if !hadPrev || prev.desc != desc {
			switch {
			case first:
			case !hadPrev:
				events = append(events,
					FDEvent{Timestamp: now, Message: fmt.Sprintf("openat fd=%d %s", fdNum, desc)},
					TimelineEvent{Timestamp: now, Category: "fd", Message: fmt.Sprintf("openat → fd=%d %s", fdNum, desc)},
				)
			default:
				events = append(events,
					FDEvent{Timestamp: now, Message: fmt.Sprintf("reuse fd=%d %s → %s", fdNum, prev.desc, desc)},
					TimelineEvent{Timestamp: now, Category: "fd", Message: fmt.Sprintf("dup/reuse fd=%d → %s", fdNum, desc)},
				)
			}
			prev = fdState{
				openedAt:    now,
				pos:         pos,
				desc:        desc,
				fdType:      fdType,
				posKnown:    fdType == "file" && hasOffset(fdPath),
				preexisting: first,
			}
		}

		// Active = pos moved since the last poll. Only an fd with an offset
		// has one to move (PosKnown): a socket's or a pipe's pos stays 0
		// whatever goes through it.
		active := prev.posKnown && pos != prev.pos
		next := prev
		next.pos = pos
		c.baseline[fdNum] = next

		entry := FDEntry{
			FD:          fdNum,
			Type:        fdType,
			Desc:        desc,
			Flags:       flags,
			AgeMs:       now.Sub(prev.openedAt).Milliseconds(),
			Active:      active,
			PosKnown:    prev.posKnown,
			Preexisting: prev.preexisting,
		}
		if prev.posKnown {
			entry.Bytes = pos
		}
		result = append(result, entry)
	}

	// Detect closes (FDs that were in baseline and disappeared)
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

// hasOffset says whether the file behind /proc/<pid>/fd/<n> has an offset
// that reads and writes move: a regular file or a block device. A character
// device (a tty, /dev/null) keeps pos at 0 whatever is written to it. The stat
// follows the fd's magic link, so it works across mount namespaces.
func hasOffset(fdPath string) bool {
	st, err := os.Stat(fdPath)
	if err != nil {
		return false
	}
	mode := st.Mode()
	return mode.IsRegular() || (mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0)
}

// inferType classifies an fd by its /proc/<pid>/fd link, as the kernel names
// it. fds 0-2 are classified like any other: a daemon's stdin is often
// /dev/null and its stdout a socket to the journal.
func inferType(link string) string {
	switch {
	case strings.HasPrefix(link, "socket:"):
		return "socket"
	case strings.HasPrefix(link, "pipe:"):
		return "pipe"
	case link == "anon_inode:[eventpoll]":
		return "epoll"
	case link == "anon_inode:[timerfd]":
		return "timer"
	case link == "anon_inode:[eventfd]":
		return "event"
	case strings.HasPrefix(link, "/"):
		return "file"
	default:
		// Every other anonymous inode (pidfd, inotify, signalfd, io_uring,
		// bpf maps, ...) and the namespace files ("net:[4026531840]"). The
		// description is the link, which names the kind.
		return "other"
	}
}

// describeLink resolves the /proc/<pid>/fd/<n> link into a human-readable
// description. Sockets become "TCP 127.0.0.1:8080" via SocketResolver.
// Other cases pass through directly.
func (c *FDCollector) describeLink(link string) string {
	if link == "" {
		return "(unknown)"
	}
	if inode, ok := extractSocketInode(link); ok {
		if info, ok := c.resolver.Resolve(inode); ok {
			return fmt.Sprintf("%s %s", info.Family, info.Remote)
		}
		// fallback while the socket isn't resolved (cache stale or weird inode)
		return link
	}
	return link
}

func readFlags(pid, fd int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "flags:") {
			flags, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "flags:")), 8, 64)
			accmode := flags & 0x3
			switch accmode {
			case 0:
				return "O_RDONLY"
			case 1:
				return "O_WRONLY"
			case 2:
				return "O_RDWR"
			}
		}
	}
	return ""
}

// readFDPos extracts the "pos:" field from /proc/<pid>/fdinfo/<fd>.
// For seekable files it's the cumulative file pointer offset; for
// sockets/pipes it's 0 and doesn't change. Used by the collector to
// infer Active.
func readFDPos(pid, fd int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "pos:") {
			s := strings.TrimSpace(strings.TrimPrefix(line, "pos:"))
			n, _ := strconv.ParseUint(s, 10, 64)
			return n
		}
	}
	return 0
}
