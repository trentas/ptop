//go:build linux || darwin

package symbol

import (
	"errors"
	"os"
	"syscall"
)

// identify keys f by the identity of the file behind it. ok is false for
// anything that is not a regular file, which is then parsed but not shared.
func identify(f *os.File) (fileKey, bool) {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return fileKey{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{
		dev:   uint64(st.Dev),
		ino:   st.Ino,
		size:  fi.Size(),
		mtime: fi.ModTime().UnixNano(),
	}, true
}

// mapFile maps the first size bytes of f read-only. The mapping outlives f.
func mapFile(f *os.File, size int64) ([]byte, error) {
	if size <= 0 || int64(int(size)) != size {
		return nil, errors.New("file size cannot be mapped")
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var b []byte
	var merr error
	if err := rc.Control(func(fd uintptr) {
		b, merr = syscall.Mmap(int(fd), 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
	}); err != nil {
		return nil, err
	}
	return b, merr
}

func unmapFile(b []byte) { _ = syscall.Munmap(b) }
