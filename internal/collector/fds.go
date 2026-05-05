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

// FDCollector lê /proc/<pid>/fd e /proc/<pid>/fdinfo a cada 500ms.
// Funciona sem root, sem eBPF — primeiro collector implementado.
//
// Publica três tipos de mensagem na mesma channel (consumidor faz
// type-switch):
//
//   - []FDEntry           — snapshot completo do estado atual (cada poll)
//   - TimelineEvent       — evento "openat fd=N <desc>" / "close fd=N" pra timeline global
//   - FDEvent             — versão compacta dedicada à F6 ▸ FD Events
type FDCollector struct {
	pid      int
	ch       chan interface{}
	stop     chan struct{}
	mu       sync.Mutex
	resolver *SocketResolver

	// estado entre polls
	baseline map[int]fdState // fd → estado da última observação
}

type fdState struct {
	openedAt time.Time
	pos      uint64 // /proc/<pid>/fdinfo/<fd> campo "pos:" — usado pra detectar atividade
	desc     string // descrição estável (path do file ou TCP IP:port resolvido)
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
	// Primeira coleta imediata pra UI não esperar 500ms pra mostrar nada
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

// collectAndEmit faz um snapshot e emite os 3 tipos de mensagem na channel.
// Eventos (open/close) são emitidos ANTES do snapshot para que a UI tenha o
// histórico antes de re-renderizar a tabela com o estado novo.
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
		// canal cheio; descarta. UI vai pegar a próxima rodada.
	}
}

// collect retorna o snapshot atual + eventos (open/close) detectados desde o
// último poll.
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
		// Detecta nova abertura (FD não estava no baseline OU mudou de descrição
		// — caso de dup2 que reusa o número)
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
			// FD foi reusado (dup2/openat depois de close) — emit close+open
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

		// Active = mudança de pos desde último poll. Faz sentido pra files;
		// pra sockets/pipes pos é constante 0, então Active fica false.
		// (eBPF futura via #11 vai dar Active correto pra qualquer fd type.)
		active := pos != prev.pos
		c.baseline[fdNum] = fdState{
			openedAt: prev.openedAt,
			pos:      pos,
			desc:     desc,
			fdType:   fdType,
		}

		bytes := pos // pra sockets/pipes ignora-se; pra files é cumulative pos

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

	// Detecta closes (FDs que estavam no baseline e sumiram)
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

// describeLink resolve o link de /proc/<pid>/fd/<n> em uma descrição legível.
// Sockets viram "TCP 127.0.0.1:8080" via SocketResolver. Outros casos passam
// direto.
func (c *FDCollector) describeLink(link string) string {
	if link == "" {
		return "(unknown)"
	}
	if inode, ok := extractSocketInode(link); ok {
		if info, ok := c.resolver.Resolve(inode); ok {
			return fmt.Sprintf("%s %s", info.Family, info.Remote)
		}
		// fallback enquanto socket não está resolvido (cache stale ou inode estranho)
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

// readFDPos extrai o campo "pos:" de /proc/<pid>/fdinfo/<fd>.
// Para arquivos seekable é o offset cumulativo do file pointer; pra
// sockets/pipes é 0 e não muda. Usado pelo collector pra inferir Active.
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
