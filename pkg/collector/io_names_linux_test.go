//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// These run against this test process's own fds: what the collector reads for
// a target, read for ourselves.

// openFile opens path for writing and returns its fd and inode number.
func openFile(t *testing.T, path string) (uint32, uint64) {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return uint32(fd), st.Ino
}

func canonical(t *testing.T, path string) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A file opened, written and closed before the collector reads its events is
// named by its open (#162). It used to read "fd=N".
func TestFileNamesClosedFileKeepsItsName(t *testing.T) {
	n := newFileNames(os.Getpid())
	now := time.Now()
	a := filepath.Join(t.TempDir(), "a.log")
	fd, ino := openFile(t, a)
	n.opened(fd, ino, atFDCWD, a, now)
	syscall.Close(int(fd))

	if got := n.name(fd, ino, now); got != canonical(t, a) {
		t.Errorf("closed file named %q, want %q", got, canonical(t, a))
	}
}

// A reused fd number is credited to the file that holds it at the event, not
// to the one that held it first (#162).
func TestFileNamesReusedNumber(t *testing.T) {
	n := newFileNames(os.Getpid())
	now := time.Now()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")

	fdA, inoA := openFile(t, a)
	n.opened(fdA, inoA, atFDCWD, a, now)
	if got := n.name(fdA, inoA, now); got != canonical(t, a) {
		t.Fatalf("a named %q", got)
	}
	syscall.Close(int(fdA))
	fdB, inoB := openFile(t, b)
	defer syscall.Close(int(fdB))
	if fdB != fdA {
		t.Skipf("the kernel did not reuse fd %d (got %d): nothing to test", fdA, fdB)
	}
	n.opened(fdB, inoB, atFDCWD, b, now)

	if got := n.name(fdB, inoB, now); got != canonical(t, b) {
		t.Errorf("b's write on reused fd %d named %q, want %q", fdB, got, canonical(t, b))
	}
	if got := n.name(fdA, inoA, now); got != canonical(t, a) {
		t.Errorf("a late event of a, on fd %d, named %q, want %q", fdA, got, canonical(t, a))
	}
}

// With no open seen (a file opened before the capture, a socket, a pipe), the
// fd's link is taken only while the fd still holds the event's inode. A
// number since reused is a gap, never the new file.
func TestFileNamesLinkCheckedAgainstTheInode(t *testing.T) {
	n := newFileNames(os.Getpid())
	now := time.Now()
	dir := t.TempDir()

	fdA, inoA := openFile(t, filepath.Join(dir, "a"))
	syscall.Close(int(fdA))
	fdB, inoB := openFile(t, filepath.Join(dir, "b"))
	defer syscall.Close(int(fdB))
	if fdB != fdA {
		t.Skipf("the kernel did not reuse fd %d (got %d): nothing to test", fdA, fdB)
	}

	if got := n.name(fdA, inoA, now); got != "" {
		t.Errorf("an event of the closed a, on reused fd %d, named %q, want unnamed", fdA, got)
	}
	if got, want := n.name(fdB, inoB, now), canonical(t, filepath.Join(dir, "b")); got != want {
		t.Errorf("b named %q, want %q", got, want)
	}

	var p [2]int
	if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(p[0])
	defer syscall.Close(p[1])
	var st syscall.Stat_t
	if err := syscall.Fstat(p[1], &st); err != nil {
		t.Fatal(err)
	}
	if got, want := n.name(uint32(p[1]), st.Ino, now), "pipe:["+strconv.FormatUint(st.Ino, 10)+"]"; got != want {
		t.Errorf("pipe named %q, want %q", got, want)
	}
}

// A relative path is made absolute against the working directory or the
// dirfd, when the file is gone by the time the open is read.
func TestFileNamesRelativeOpen(t *testing.T) {
	n := newFileNames(os.Getpid())
	now := time.Now()
	dir := canonical(t, t.TempDir())

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	n.opened(90, 1001, atFDCWD, "logs/x.log", now)
	if got, want := n.name(90, 1001, now), filepath.Join(cwd, "logs/x.log"); got != want {
		t.Errorf("relative to the cwd: %q, want %q", got, want)
	}

	dfd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(dfd)
	n.opened(91, 1002, int32(dfd), "y.tmp", now)
	if got, want := n.name(91, 1002, now), filepath.Join(dir, "y.tmp"); got != want {
		t.Errorf("relative to dirfd %d: %q, want %q", dfd, got, want)
	}
}

// A file unlinked while still open keeps the name it was opened by, not the
// kernel's "(deleted)" link.
func TestFileNamesDeletedWhileOpen(t *testing.T) {
	n := newFileNames(os.Getpid())
	now := time.Now()
	a := filepath.Join(canonical(t, t.TempDir()), "scratch")
	fd, ino := openFile(t, a)
	defer syscall.Close(int(fd))
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	n.opened(fd, ino, atFDCWD, a, now)
	if got := n.name(fd, ino, now); got != a {
		t.Errorf("named %q, want %q", got, a)
	}
}

// Cgroup mode names nothing: there is no single process to read from.
func TestFileNamesCgroupModeNamesNothing(t *testing.T) {
	n := newFileNames(0)
	now := time.Now()
	n.opened(3, 42, atFDCWD, "/etc/hosts", now)
	if got := n.name(3, 42, now); got != "" {
		t.Errorf("cgroup mode named %q", got)
	}
}

// Names nobody asks for expire; one in use does not.
func TestFileNamesPrune(t *testing.T) {
	n := newFileNames(os.Getpid())
	t0 := time.Now()
	n.opened(90, 1, atFDCWD, "/gone/a", t0)
	n.opened(91, 2, atFDCWD, "/gone/b", t0)
	n.name(91, 2, t0.Add(fileNameTTL/2))
	n.prune(t0.Add(fileNameTTL + time.Second))
	if _, ok := n.byKey[fileKey{90, 1}]; ok {
		t.Error("an unused name outlived its TTL")
	}
	if _, ok := n.byKey[fileKey{91, 2}]; !ok {
		t.Error("a name in use was dropped")
	}
}

// fdIno reads the inode the probe reads.
func TestFdInoMatchesFstat(t *testing.T) {
	fd, ino := openFile(t, filepath.Join(t.TempDir(), "f"))
	defer syscall.Close(int(fd))
	got, ok := fdIno(os.Getpid(), fd)
	if !ok || got != ino {
		t.Errorf("fdIno = %d, %v; want %d", got, ok, ino)
	}
	if _, ok := fdIno(os.Getpid(), 1<<20); ok {
		t.Error("fdIno read an fd that is not open")
	}
}
