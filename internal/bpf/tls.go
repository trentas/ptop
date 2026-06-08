//go:build linux && ebpf

package bpf

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed programs/tls.bpf.o
var tlsBPFObj []byte

// tlsMaxData mirrors TLS_MAX_DATA in programs/tls.bpf.c — the hard per-call
// capture cap and the fixed size of the event's data buffer.
const tlsMaxData = 4096

// TLS payload directions — mirror TLS_DIR_* in programs/tls.bpf.c.
const (
	TLSDirWrite uint32 = 0
	TLSDirRead  uint32 = 1
)

// TLSEventRecord is the 1:1 layout of struct tls_event in programs/tls.bpf.c
// (#55). Fixed size 4128 bytes; binary.LittleEndian parses it from the ring
// buffer. Only the first Captured bytes of Data are valid.
type TLSEventRecord struct {
	TsNs     uint64
	TGID     uint32
	PID      uint32
	FD       int32
	Dir      uint32
	Len      int32
	Captured uint32
	Data     [tlsMaxData]byte
}

// TLSTracer loads tls.bpf.o and attaches uprobes on the target's libssl
// (SSL_write/SSL_read/SSL_set_fd), exposing Next() to deliver parsed payload
// events. Capture is bounded by maxBytes (0 = metadata only).
type TLSTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader
}

// OpenTLSTracer resolves the target's libssl, writes the target filter + the
// capture cap, attaches the SSL uprobes (best-effort; at least one of
// SSL_write/SSL_read must attach), and opens the event ring buffer. Returns an
// error when no libssl is mapped (no OpenSSL/BoringSSL, static, or Go target),
// leaving the collector inactive.
func OpenTLSTracer(pid, maxBytes int) (*TLSTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	libsslPath, err := resolveLibSSL(pid)
	if err != nil {
		return nil, err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tlsBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse tls BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load tls collection: %w", err)
	}
	t := &TLSTracer{coll: coll}

	targetMap := coll.Maps["tls_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("tls_target_pid map missing")
	}
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set tls_target_pid: %w", err)
	}

	// Capture cap (--tls-bytes), clamped to the buffer size. 0 = metadata only.
	cfgMap := coll.Maps["tls_cfg"]
	if cfgMap == nil {
		t.Close()
		return nil, errors.New("tls_cfg map missing")
	}
	cap32 := uint32(maxBytes)
	if maxBytes < 0 {
		cap32 = 0
	}
	// Clamp to TLS_MAX_DATA-1: the BPF side bounds the copy with a mask of
	// (TLS_MAX_DATA-1), so a cap of exactly TLS_MAX_DATA would mask to 0.
	if cap32 > tlsMaxData-1 {
		cap32 = tlsMaxData - 1
	}
	var key uint32
	if err := cfgMap.Update(&key, &cap32, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set tls_cfg: %w", err)
	}

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("open libssl %s: %w", libsslPath, err)
	}

	opts := &link.UprobeOptions{PID: pid}
	probes := []struct {
		sym, prog string
		ret       bool
	}{
		{"SSL_write", "uprobe_ssl_write", false},
		{"SSL_read", "uprobe_ssl_read", false},
		{"SSL_read", "uretprobe_ssl_read", true},
		{"SSL_set_fd", "uprobe_ssl_set_fd", false},
	}
	var haveWrite, haveRead bool
	for _, p := range probes {
		prog := coll.Programs[p.prog]
		if prog == nil {
			t.Close()
			return nil, fmt.Errorf("program %s missing", p.prog)
		}
		var l link.Link
		if p.ret {
			l, err = ex.Uretprobe(p.sym, prog, opts)
		} else {
			l, err = ex.Uprobe(p.sym, prog, opts)
		}
		if err != nil {
			// Tolerate a missing symbol (BoringSSL/version drift); we only
			// need one of SSL_write/SSL_read to be useful.
			fmt.Fprintf(os.Stderr, "warning: tls uprobe %s (%s): %v\n", p.sym, p.prog, err)
			continue
		}
		t.links = append(t.links, l)
		if p.sym == "SSL_write" {
			haveWrite = true
		}
		if p.sym == "SSL_read" && !p.ret {
			haveRead = true
		}
	}
	if !haveWrite && !haveRead {
		t.Close()
		return nil, fmt.Errorf("could not attach SSL_write/SSL_read uprobes on %s", libsslPath)
	}

	eventsMap := coll.Maps["tls_events"]
	if eventsMap == nil {
		t.Close()
		return nil, errors.New("tls_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// Next blocks until the next TLS payload event arrives. Returns io.EOF when the
// tracer is closed; a short/garbled record is reported as an error without
// closing the stream.
func (t *TLSTracer) Next() (TLSEventRecord, error) {
	var ev TLSEventRecord
	if t == nil || t.rb == nil {
		return ev, errors.New("tracer not initialized")
	}
	rec, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ev, io.EOF
		}
		return ev, err
	}
	if len(rec.RawSample) < 4128 {
		return ev, fmt.Errorf("short tls event: %d bytes", len(rec.RawSample))
	}
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode tls event: %w", err)
	}
	return ev, nil
}

func (t *TLSTracer) Close() error {
	if t == nil {
		return nil
	}
	if t.rb != nil {
		_ = t.rb.Close()
		t.rb = nil
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
	}
	return nil
}

// resolveLibSSL finds the libssl mapped into pid and returns the file path to
// attach uprobes against, preferring the target's mount-namespace view (so the
// symbol offsets match the running library). Errors when none is mapped (no
// OpenSSL/BoringSSL, statically linked, or a Go target whose crypto/tls is pure
// Go) — the caller then leaves the TLS collector inactive.
func resolveLibSSL(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", fmt.Errorf("open maps of %d: %w", pid, err)
	}
	defer f.Close()

	var path string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		p := strings.Join(fields[5:], " ")
		if strings.HasPrefix(filepath.Base(p), "libssl.so") {
			path = p
			break
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if path == "" {
		return "", errors.New("no libssl mapped (no OpenSSL/BoringSSL, static, or Go crypto/tls)")
	}

	rooted := fmt.Sprintf("/proc/%d/root%s", pid, path)
	if _, e := os.Stat(rooted); e == nil {
		return rooted, nil
	}
	return path, nil
}
