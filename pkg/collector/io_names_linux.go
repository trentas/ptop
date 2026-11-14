//go:build linux

package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// fileNames names the file a read or write hit as it was when the call ran,
// not when the collector got round to the event (#162).
//
// The io collector used to readlink /proc/<pid>/fd/<n> when it processed an
// event, and remember the answer by fd number for two seconds. Two wrong
// answers followed. A file closed by then had no link left, so its writes went
// to a row named "fd=N" — logs, temp files, most config writes. And `open`
// hands out the lowest free number, so a new file written within two seconds
// of an old one on the same number was credited to the old one, deleted or
// not. The selftest met it: a per-CPU file whose number a zero-length write to
// another file had cached read 0 writes for 20 planted.
//
// So the probe now says which file it was: each event carries the inode
// number of the file behind its fd, read in the kernel when the call entered,
// and each successful open arrives, before any call on its fd, with the path
// the program passed. Names are keyed by (fd, inode), and come from:
//
//   - the open, for a file opened during the capture. Its fd's link is used
//     when it still points at that inode, since it is the kernel's canonical
//     path; otherwise the path as passed, made absolute against the working
//     directory or the dirfd.
//   - the fd's link, for one opened before the capture (or by a call the probe
//     does not see: socket, pipe, accept, dup), taken only when
//     /proc/<pid>/fdinfo/<n> still reports the event's inode. A number reused
//     since reads as "fd=N", which is a gap; crediting the new file would be a
//     wrong answer.
//
// The key has no device, so two files with one inode number on two
// filesystems, behind the same fd number in turn, are not told apart; nor are
// two anonymous inodes (an eventfd and a timerfd share one). Both need the
// number reused between an event and the collector reading it.
//
// In cgroup mode there is no pid (0) and nothing is named, as before: the key
// would need the process too, and the paths would be read from many.
//
// Not safe for concurrent use: the collector's read loop is its only caller.
type fileNames struct {
	pid   int
	byKey map[fileKey]*fileName
	// lastPrune is when names unused for fileNameTTL were last dropped.
	lastPrune time.Time
}

type fileKey struct {
	fd  uint32
	ino uint64
}

type fileName struct {
	name string
	used time.Time
}

// fileNameTTL is how long a name nobody asked for is kept. Expiry costs only a
// lookup: the next event on a file still open is named from its link again.
const fileNameTTL = 10 * time.Second

func newFileNames(pid int) *fileNames {
	return &fileNames{pid: pid, byKey: make(map[fileKey]*fileName)}
}

// opened records the file a successful open installed at fd: path as the
// program passed it, relative to dfd.
func (n *fileNames) opened(fd uint32, ino uint64, dfd int32, path string, now time.Time) {
	n.prune(now)
	if ino == 0 || n.pid <= 0 {
		return // no identity to key it by; the events on fd fall back to the link
	}
	name := ""
	if link, ok := n.linkIfIno(fd, ino); ok && !strings.HasSuffix(link, " (deleted)") {
		name = link
	} else {
		name = n.absolute(dfd, path)
	}
	if name == "" {
		return
	}
	n.byKey[fileKey{fd, ino}] = &fileName{name: name, used: now}
}

// name is the file behind fd for an event that read inode ino there, or "" when
// it cannot be told.
func (n *fileNames) name(fd uint32, ino uint64, now time.Time) string {
	n.prune(now)
	if n.pid <= 0 {
		return ""
	}
	if ino == 0 {
		// The kernel could not read the fd table, so there is nothing to check
		// the link against: take it as it is now, and remember nothing.
		link, _ := os.Readlink(n.fdPath("fd", fd))
		return link
	}
	k := fileKey{fd, ino}
	if e, ok := n.byKey[k]; ok {
		e.used = now
		return e.name
	}
	link, ok := n.linkIfIno(fd, ino)
	if !ok {
		return ""
	}
	n.byKey[k] = &fileName{name: link, used: now}
	return link
}

// linkIfIno is fd's link, if fd still holds inode ino.
func (n *fileNames) linkIfIno(fd uint32, ino uint64) (string, bool) {
	link, err := os.Readlink(n.fdPath("fd", fd))
	if err != nil {
		return "", false
	}
	// Read after the link: if the number was reused in between, the inode
	// read here is the newer file's and the check fails, so a stale link is
	// never taken.
	cur, ok := fdIno(n.pid, fd)
	if !ok || cur != ino {
		return "", false
	}
	return link, true
}

// absolute makes path absolute against dfd: the working directory for
// AT_FDCWD, or the directory dfd holds. A base that cannot be read leaves the
// path as the program passed it, which still names the file.
func (n *fileNames) absolute(dfd int32, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	var base string
	var err error
	if dfd == atFDCWD {
		base, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", n.pid))
	} else {
		base, err = os.Readlink(n.fdPath("fd", uint32(dfd)))
	}
	if err != nil || !filepath.IsAbs(base) {
		return path
	}
	return filepath.Join(base, path)
}

// atFDCWD is AT_FDCWD as the kernel passes it in openat's dirfd.
const atFDCWD = -100

func (n *fileNames) fdPath(dir string, fd uint32) string {
	return fmt.Sprintf("/proc/%d/%s/%d", n.pid, dir, fd)
}

// prune drops names unused for fileNameTTL, at most once a second.
func (n *fileNames) prune(now time.Time) {
	if now.Sub(n.lastPrune) < time.Second {
		return
	}
	n.lastPrune = now
	for k, e := range n.byKey {
		if now.Sub(e.used) > fileNameTTL {
			delete(n.byKey, k)
		}
	}
}

// fdIno is the inode number of the file pid holds at fd: the `ino:` line of
// /proc/<pid>/fdinfo/<fd>, which is file_inode(f)->i_ino, the same field the
// probe reads. Kernels before 5.14 print no such line; there the link's own
// inode, by stat, stands in. It differs only on a stacked filesystem.
func fdIno(pid int, fd uint32) (uint64, bool) {
	if f, err := os.Open(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd)); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "ino:"); ok {
				ino, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
				return ino, err == nil
			}
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd), &st); err != nil {
		return 0, false
	}
	return st.Ino, true
}
