//go:build linux

package collector

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

// ProcContextCollector reads the target's execution/container context from
// /proc — uid/gid (status), namespace inodes (ns/*), and the cgroup path — and
// publishes a ProcContext snapshot once at start and then periodically. It is a
// pure /proc collector (no eBPF, no caps), so it runs in --no-ebpf mode too. The
// context of a single target is essentially fixed, so the period is relaxed; a
// refresh still catches setuid/setns/cgroup-move during the process's life.
type ProcContextCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	once sync.Once
}

// procContextInterval is the refresh period. The target's ns/cgroup/uid rarely
// change, so this is deliberately slow — it exists to catch the occasional
// setuid/setns, not to poll hot.
const procContextInterval = 3 * time.Second

// cgroupRoot is the cgroup-v2 unified mount point. Used to resolve a cgroup
// path to its directory inode (the cgroup id).
const cgroupRoot = "/sys/fs/cgroup"

func NewProcContextCollector() *ProcContextCollector {
	return &ProcContextCollector{
		ch:   make(chan interface{}, 4),
		stop: make(chan struct{}),
	}
}

func (c *ProcContextCollector) Start(pid int) error {
	c.pid = pid
	// status is the cheapest existence check that also proves we can read the
	// target's /proc entries at all.
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err != nil {
		return fmt.Errorf("process %d /proc unreadable: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *ProcContextCollector) Stop() {
	c.once.Do(func() { close(c.stop) })
}

func (c *ProcContextCollector) Subscribe() <-chan interface{} { return c.ch }

func (c *ProcContextCollector) loop() {
	c.publish() // immediate first snapshot — the header/badge fills in at once
	t := time.NewTicker(procContextInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.publish()
		}
	}
}

// publish samples the current context and sends it non-blocking. A read error
// for a single field degrades that field to its zero value rather than dropping
// the whole snapshot — a process may briefly hide a /proc entry without meaning
// the rest is unavailable.
func (c *ProcContextCollector) publish() {
	pc := c.sample()
	select {
	case c.ch <- pc:
	default:
	}
}

func (c *ProcContextCollector) sample() ProcContext {
	pc := ProcContext{Timestamp: time.Now()}

	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", c.pid)); err == nil {
		pc.UID, pc.GID = parseStatusUIDGID(string(data))
	}

	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", c.pid)); err == nil {
		pc.Cgroup = parseCgroup(string(data))
		pc.Container = deriveContainer(pc.Cgroup)
		pc.CgroupID = cgroupInode(pc.Cgroup)
	}

	pc.PIDNS = c.nsInode("pid")
	pc.NetNS = c.nsInode("net")
	pc.MntNS = c.nsInode("mnt")
	pc.UserNS = c.nsInode("user")
	pc.CgroupNS = c.nsInode("cgroup")
	pc.IPCNS = c.nsInode("ipc")
	pc.UTSNS = c.nsInode("uts")

	return pc
}

// nsInode resolves the inode of /proc/<pid>/ns/<kind> from its symlink target
// ("kind:[<inode>]"). Returns 0 when the namespace isn't accessible (e.g. the
// kind is unsupported, or we lack permission).
func (c *ProcContextCollector) nsInode(kind string) uint64 {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", c.pid, kind))
	if err != nil {
		return 0
	}
	return parseNSInode(link)
}

// cgroupInode returns the directory inode of a cgroup-v2 path under the unified
// mount — the same value bpf_get_current_cgroup_id() reports, so it correlates
// with eBPF-side ids. Returns 0 for the empty path or when the directory can't
// be stat'd (cgroup v1's per-controller layout, or no unified mount).
func cgroupInode(path string) uint64 {
	if path == "" {
		return 0
	}
	var st syscall.Stat_t
	if err := syscall.Stat(cgroupRoot+path, &st); err != nil {
		return 0
	}
	return st.Ino
}
