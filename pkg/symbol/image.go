package symbol

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"weak"
)

// One parse per file, and the big sections mapped rather than copied (#137).
//
// A Go binary's .gopclntab is a large fraction of the file — 131.6 MB of a
// 394 MB otelcol-contrib — and gosym's table built over it is about as large
// again (~130 MB for that binary). Before #137 every Symbolizer opened its own
// Module and every Module copied the section onto the heap. The heap, futex,
// security and cpuprof collectors each held a Symbolizer, and the Go
// allocation probe and ProcessBuildID opened the executable again on their
// own, so a single capture kept up to four copies and four tables alive and
// made two more transient ones: ~1.1 GB, against a 512 MiB container sized for
// small targets, which the kernel OOM-killed purely for opening one binary
// several times.
//
// Two changes, each needed:
//
//   - The image is shared. A Module is now a name plus a pointer to an image,
//     and images are cached by file identity — device, inode, size and mtime,
//     which is what "the same contents" means for a file nobody is rewriting.
//     Collectors that open the same executable get one parse between them,
//     whatever path each opened it by.
//   - The large sections are mapped. .gopclntab and the DWARF sections are
//     slices of a read-only mapping of the file, not heap copies. Their pages
//     are file-backed, so the kernel can reclaim them under pressure instead
//     of counting them as anonymous memory. Only the pages a lookup touches
//     are read in, and they are the same page-cache pages the target maps
//     from the same file.
//
// The cache holds images WEAKLY. An image lives exactly as long as some Module
// refers to it, so a Symbolizer released with its target releases the parse
// with it, and a server that has watched a hundred short-lived targets (#72)
// holds nothing for the ninety-nine that are gone. A cleanup unmaps the file
// once the image is unreachable.
//
// What a shared parse cannot remove is the gosym table itself — one per
// binary, on the heap, proportional to how many functions the binary has. It
// is the next lever if a target outgrows a budget: gosym materializes every
// function up front, where a lookup needs only the one it lands in.
//
// One rule follows from the mapping, for anything added here: nothing may keep
// a slice of the mapped sections past the image's lifetime, because the
// cleanup unmaps them and the slice would then fault. gosym and debug/dwarf
// copy every string they hand out, and Frame carries only strings, which is
// what makes the current set safe.

// images is the process-wide cache behind OpenModule.
var images = &imageCache{slots: make(map[fileKey]*imageSlot)}

// fileKey identifies a file's contents without reading them. Size and mtime
// are there for a file rewritten in place, which keeps its inode.
type fileKey struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

type imageCache struct {
	mu    sync.Mutex
	slots map[fileKey]*imageSlot
}

// imageSlot is one file's entry. done closes once the first opener finished
// parsing; img is then the result, held weakly, or err says why there is none.
type imageSlot struct {
	done chan struct{}
	img  weak.Pointer[image]
	err  error
}

// loadImage returns r's image: from the cache when r is a file another Module
// already holds, freshly parsed otherwise.
func loadImage(r io.ReaderAt, name string) (*image, error) {
	f, ok := r.(*os.File)
	if !ok {
		return parseImage(r, name, (*elf.Section).Data)
	}
	key, ok := identify(f)
	if !ok {
		return parseImage(r, name, (*elf.Section).Data)
	}
	return images.get(key, func() (*image, error) { return parseMapped(f, key.size, name) })
}

// get returns the image cached for key, running parse to produce it when there
// is none. Concurrent callers for one key wait for a single parse rather than
// each starting their own: the collectors of one target reach their first
// frame within the same publish tick, and a parse apiece is the peak #137 is
// about.
func (c *imageCache) get(key fileKey, parse func() (*image, error)) (*image, error) {
	for {
		c.mu.Lock()
		s, found := c.slots[key]
		if !found {
			s = &imageSlot{done: make(chan struct{})}
			c.slots[key] = s
		}
		c.mu.Unlock()

		if !found {
			return c.fill(key, s, parse)
		}
		<-s.done
		if img := s.img.Value(); img != nil {
			return img, nil
		}
		if s.err != nil {
			return nil, s.err
		}
		// Collected since it was parsed (or the parse panicked): drop the dead
		// slot and parse again.
		c.drop(key, s)
	}
}

// fill runs the parse for a slot this caller created, and publishes the result
// to anyone waiting on it. A failure is handed to the waiters but not kept:
// the next opener tries again, as it would have before the cache existed.
func (c *imageCache) fill(key fileKey, s *imageSlot, parse func() (*image, error)) (img *image, err error) {
	defer func() {
		if img != nil {
			s.img = weak.Make(img)
			runtime.AddCleanup(img, func(s *imageSlot) { c.drop(key, s) }, s)
		} else {
			s.err = err
			c.drop(key, s)
		}
		close(s.done)
	}()
	return parse()
}

// drop removes s, unless key has moved on to a newer slot.
func (c *imageCache) drop(key fileKey, s *imageSlot) {
	c.mu.Lock()
	if c.slots[key] == s {
		delete(c.slots, key)
	}
	c.mu.Unlock()
}

// parseMapped parses f with its large sections served from a mapping of it, and
// arranges for the mapping to outlive the file handle and to be released with
// the image.
func parseMapped(f *os.File, size int64, name string) (*image, error) {
	src := &sectionSource{file: f, size: size}
	img, err := parseImage(f, name, src.data)
	if err != nil || !src.used {
		src.release()
		return img, err
	}
	img.mapping = src.mapping
	runtime.AddCleanup(img, unmapFile, src.mapping)
	return img, nil
}

// sectionSource hands out section contents as slices of one read-only mapping
// of the file, made the first time a section asks for it. A section it cannot
// serve that way — compressed, or past the end of the file — and any failure
// to map, fall back to Section.Data, which is exactly what OpenModule did
// before #137.
type sectionSource struct {
	file    *os.File
	size    int64
	mapping []byte
	failed  bool
	used    bool // some section was handed out as a slice of the mapping
}

func (s *sectionSource) data(sec *elf.Section) ([]byte, error) {
	if b, ok := s.mapped(sec); ok {
		s.used = true
		return b, nil
	}
	return sec.Data()
}

func (s *sectionSource) mapped(sec *elf.Section) ([]byte, bool) {
	// A compressed section's file bytes are not its contents; Data inflates them.
	if s.failed || sec.Flags&elf.SHF_COMPRESSED != 0 || sec.FileSize != sec.Size {
		return nil, false
	}
	if s.mapping == nil {
		m, err := mapFile(s.file, s.size)
		if err != nil {
			s.failed = true
			return nil, false
		}
		s.mapping = m
	}
	end := sec.Offset + sec.FileSize
	if end < sec.Offset || end > uint64(len(s.mapping)) {
		return nil, false
	}
	return s.mapping[sec.Offset:end:end], true
}

// release unmaps a mapping nothing ended up using.
func (s *sectionSource) release() {
	if s.mapping != nil {
		unmapFile(s.mapping)
		s.mapping = nil
	}
}

// endFaultGuard is deferred, with the previous SetPanicOnFault setting, by
// every method that reads the mapped file.
//
// A mapping is only as good as the file under it: if the file is truncated
// while mapped, touching a page past the new end raises SIGBUS, and by default
// the Go runtime dies of it. ptop never writes these files, and for the
// target's own executable the kernel refuses writes while it runs — but a
// shared library or a symbol bundle has no such protection, and a collector
// must not take the process down over a frame. SetPanicOnFault exists for
// exactly this (its documentation names memory-mapped files): the fault
// becomes a panic, recovered here, and the lookup returns what it had.
//
// Panics that are not faults are not ours to swallow, and are re-raised.
func (m *image) endFaultGuard(name string, prev bool) {
	debug.SetPanicOnFault(prev)
	r := recover()
	if r == nil {
		return
	}
	if _, fault := r.(interface{ Addr() uintptr }); !fault {
		panic(r)
	}
	m.faultOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "[ptop] symbols: %s changed on disk while mapped; frames in it may resolve without names\n", name)
	})
}
