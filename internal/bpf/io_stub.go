//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"io"
	"time"
)

var errIOStub = errors.New("eBPF io tracer not available in this build")

const (
	IORecOpen  uint32 = 0
	IORecSeen  uint32 = 1
	IORecClose uint32 = 2
)

const IOStatsMax = 16384

const IOBuckets = 5

const (
	IOOpRead  = 0
	IOOpWrite = 1
)

type IORecord struct {
	Kind uint32
	TGID uint32
	FD   uint32
	Dfd  int32
	Ino  uint64
	Gen  uint64
	Path string
	Stat IOStat
}

func (r IORecord) Key() IOKey { return IOKey{TGID: r.TGID, FD: r.FD, Ino: r.Ino} }

type IOKey struct {
	TGID uint32
	FD   uint32
	Ino  uint64
}

type IOStat struct {
	Gen    uint64
	Reads  uint64
	Writes uint64
	Bytes  uint64
	LatNs  uint64
}

type IOTotals struct {
	Hist       [2][IOBuckets]uint64
	LostReads  uint64
	LostWrites uint64
	LostBytes  uint64
	LostLatNs  uint64
}

type IOTracer struct{}

func OpenIOTracer(Target) (*IOTracer, error)             { return nil, errIOStub }
func (*IOTracer) Next() (IORecord, error)                { return IORecord{}, io.EOF }
func (*IOTracer) SetDeadline(time.Time)                  {}
func (*IOTracer) Stats() (map[IOKey]IOStat, error)       { return nil, errIOStub }
func (*IOTracer) Totals() (IOTotals, error)              { return IOTotals{}, errIOStub }
func (*IOTracer) RetireStat(IOKey) (IOStat, bool, error) { return IOStat{}, false, errIOStub }
func (*IOTracer) Interrupt()                             {}
func (*IOTracer) Close() error                           { return nil }
