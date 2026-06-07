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
// Publishes three message types on the same channel (consumer does
// type-switch):
//
//   - []FDEntry           — full snapshot of current state (every poll)
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
}

type fdState struct {
	openedAt time.Time
	pos      uint64 // /proc/<pid>/fdinfo/<fd> "pos:" field — used to detect activity
	desc     string // stable description (file path or resolved TCP IP:port)
	fdType   string
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
	c.emit(fds)
}

func (c *FDCollector) emit(msg interface{}) {
	select {
	case c.ch <- msg:
	default:
		// channel full; drop. UI will pick up the next round.
	}
}

// collect returns the current snapshot + events (open/close) detected
// since the last poll.
func (c *FDCollector) collect() ([]FDEntry, []interface{}, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", c.pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	seen := make(map[int]bool, len(entries))
	result := make([]FDEntry, 0, len(entries))
	events := make([]interface{}, 0)

	for _, e := range entries {
		fdNum, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		seen[fdNum] = true

		link, _ := os.Readlink(filepath.Join(fdDir, e.Name()))
		fdType := inferType(fdNum, link)
		desc := c.describeLink(link)
		flags := readFlags(c.pid, fdNum)
		pos := readFDPos(c.pid, fdNum)

		prev, hadPrev := c.baseline[fdNum]
		// Detect new opens (FD wasn't in baseline OR description changed
		// — case of dup2 reusing the number)
		if !hadPrev {
			openedAt := now
			c.baseline[fdNum] = fdState{
				openedAt: openedAt,
				pos:      pos,
				desc:     desc,
				fdType:   fdType,
			}
			prev = c.baseline[fdNum]
			events = append(events,
				FDEvent{Timestamp: now, Message: fmt.Sprintf("openat fd=%d %s", fdNum, desc)},
				TimelineEvent{Timestamp: now, Category: "fd", Message: fmt.Sprintf("openat → fd=%d %s", fdNum, desc)},
			)
		} else if prev.desc != desc {
			// FD got reused (dup2/openat after close) — emit close+open
			events = append(events,
				FDEvent{Timestamp: now, Message: fmt.Sprintf("reuse fd=%d %s → %s", fdNum, prev.desc, desc)},
				TimelineEvent{Timestamp: now, Category: "fd", Message: fmt.Sprintf("dup/reuse fd=%d → %s", fdNum, desc)},
			)
			c.baseline[fdNum] = fdState{
				openedAt: now,
				pos:      pos,
				desc:     desc,
				fdType:   fdType,
			}
			prev = c.baseline[fdNum]
		}

		// Active = pos changed since last poll. Makes sense for files;
		// for sockets/pipes pos is always 0, so Active stays false.
		// (Future eBPF via #11 will give correct Active for any fd type.)
		active := pos != prev.pos
		c.baseline[fdNum] = fdState{
			openedAt: prev.openedAt,
			pos:      pos,
			desc:     desc,
			fdType:   fdType,
		}

		bytes := pos // for sockets/pipes ignored; for files it's cumulative pos

		result = append(result, FDEntry{
			FD:     fdNum,
			Type:   fdType,
			Desc:   desc,
			Flags:  flags,
			Bytes:  bytes,
			AgeMs:  now.Sub(prev.openedAt).Milliseconds(),
			Active: active,
		})
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

func inferType(fd int, link string) string {
	switch {
	case fd <= 2:
		return "pipe"
	case strings.HasPrefix(link, "socket:"):
		return "socket"
	case strings.HasPrefix(link, "pipe:"):
		return "pipe"
	case strings.HasPrefix(link, "anon_inode:[eventfd]"):
		return "event"
	case strings.HasPrefix(link, "anon_inode:[epoll]"):
		return "epoll"
	case strings.HasPrefix(link, "anon_inode:[timerfd]"):
		return "timer"
	default:
		return "file"
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
