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

// FDCollector lê /proc/{pid}/fd e /proc/{pid}/fdinfo sem precisar de eBPF.
// É o primeiro collector a implementar — funciona sem root.
type FDCollector struct {
	pid      int
	ch       chan interface{}
	stop     chan struct{}
	mu       sync.Mutex
	baseline map[int]time.Time // fd → tempo de abertura estimado
}

func NewFDCollector() *FDCollector {
	return &FDCollector{
		ch:       make(chan interface{}, 64),
		stop:     make(chan struct{}),
		baseline: make(map[int]time.Time),
	}
}

func (c *FDCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/fd", pid)); err != nil {
		return fmt.Errorf("processo %d não encontrado: %w", pid, err)
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
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			if fds, err := c.collect(); err == nil {
				select {
				case c.ch <- fds:
				default:
				}
			}
		}
	}
}

func (c *FDCollector) collect() ([]FDEntry, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", c.pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	seen := make(map[int]bool)
	var result []FDEntry

	for _, e := range entries {
		fdNum, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		seen[fdNum] = true

		// registra tempo de abertura na primeira vez que vemos o fd
		if _, ok := c.baseline[fdNum]; !ok {
			c.baseline[fdNum] = now
		}

		link, _ := os.Readlink(filepath.Join(fdDir, e.Name()))
		entry := FDEntry{
			FD:    fdNum,
			Type:  inferType(fdNum, link),
			Desc:  describeLink(link),
			Flags: readFlags(c.pid, fdNum),
			AgeMs: now.Sub(c.baseline[fdNum]).Milliseconds(),
		}
		result = append(result, entry)
	}

	// limpa baseline de fds que foram fechados
	for fd := range c.baseline {
		if !seen[fd] {
			delete(c.baseline, fd)
		}
	}

	return result, nil
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

func describeLink(link string) string {
	if link == "" {
		return "(unknown)"
	}
	// para sockets o link é "socket:[inode]" — idealmente resolvemos via /proc/net/tcp
	// por agora retorna o link diretamente
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
