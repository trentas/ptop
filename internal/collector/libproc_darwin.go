//go:build darwin

// libproc_darwin.go is the cgo foundation for the macOS port. It wraps the
// libproc(3) API and a handful of Mach helpers behind idiomatic Go types so
// the collectors don't touch cgo directly.
//
// Why libproc and not /proc-equivalent shims: macOS has no /proc filesystem.
// libproc is the public, stable userspace path that ps, top, lsof and
// Activity Monitor sit on top of. It doesn't need root, entitlements or SIP
// modifications for processes owned by the same user — the constraint we
// chose for the Tier 1 port (issue #22).
//
// Units gotcha: pti_total_user / pti_total_system / pth_user_time /
// pth_system_time are in **mach_absolute_time ticks**, NOT nanoseconds and
// NOT microseconds. On Apple Silicon (M-series) the timebase is 125/3, so
// 1 tick = ~41.67 ns. On Intel Macs the timebase is 1/1 so ticks==ns. We
// apply the timebase once at startup and convert all task/thread times to
// nanoseconds before returning to Go callers.

package collector

/*
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach/mach_time.h>

// Captured at init via mach_timebase_info — used to convert mach absolute
// time ticks (the units of pti_total_user etc.) into nanoseconds.
static uint32_t mach_tb_numer = 1;
static uint32_t mach_tb_denom = 1;
static int mach_tb_loaded = 0;

static void load_mach_timebase(void) {
    if (mach_tb_loaded) return;
    mach_timebase_info_data_t tb;
    if (mach_timebase_info(&tb) == 0) {
        mach_tb_numer = tb.numer;
        mach_tb_denom = tb.denom;
    }
    mach_tb_loaded = 1;
}

// mach_ticks_to_ns converts a mach absolute-time tick count to nanoseconds.
// Multiplication-then-division minimizes precision loss; uint64 holds the
// intermediate product for any sane CPU-time field (years of CPU on Apple
// Silicon stay well under uint64 range).
static uint64_t mach_ticks_to_ns(uint64_t ticks) {
    load_mach_timebase();
    return ticks * (uint64_t)mach_tb_numer / (uint64_t)mach_tb_denom;
}

// Helper: invoke proc_pidinfo and report success/failure as -1/+nbytes so cgo
// callers can read errno from the returned tuple. We can't read errno across
// cgo boundaries reliably without a shim that captures it before the next
// runtime call.
static int wrap_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buf, int bufsize, int *out_errno) {
    int n = proc_pidinfo(pid, flavor, arg, buf, bufsize);
    if (n <= 0) { *out_errno = errno; }
    return n;
}

static int wrap_proc_pidfdinfo(int pid, int fd, int flavor, void *buf, int bufsize, int *out_errno) {
    int n = proc_pidfdinfo(pid, fd, flavor, buf, bufsize);
    if (n <= 0) { *out_errno = errno; }
    return n;
}

static int wrap_proc_pid_rusage(int pid, int flavor, rusage_info_t *buf, int *out_errno) {
    int rc = proc_pid_rusage(pid, flavor, buf);
    if (rc != 0) { *out_errno = errno; }
    return rc;
}

static int wrap_proc_name(int pid, void *buf, uint32_t bufsize, int *out_errno) {
    int n = proc_name(pid, buf, bufsize);
    if (n <= 0) { *out_errno = errno; }
    return n;
}

// inet_ntop for IPv4 / IPv6 addresses pulled from socket_fdinfo. Returns
// length written or -1 on error.
static int fmt_v4(const struct in_addr *a, char *out, size_t n) {
    if (inet_ntop(AF_INET, a, out, n) == NULL) return -1;
    return (int)strlen(out);
}
static int fmt_v6(const struct in6_addr *a, char *out, size_t n) {
    if (inet_ntop(AF_INET6, a, out, n) == NULL) return -1;
    return (int)strlen(out);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// ─── TaskInfo (PROC_PIDTASKINFO) ─────────────────────────────────────────────

// LPTaskInfo is the per-process snapshot returned by proc_pidinfo(PROC_PIDTASKINFO).
// Time fields are in NANOSECONDS after timebase conversion (see file header).
// Sizes are in bytes.
//
// The "LP" prefix marks libproc-layer types; collectors translate them into
// the public types from types.go (CpuSample, MemStats, etc.). Without the
// prefix, ThreadInfo would collide with the public collector.ThreadInfo.
type LPTaskInfo struct {
	UserTimeNs    uint64 // pti_total_user, converted from mach ticks
	SystemTimeNs  uint64 // pti_total_system, converted from mach ticks
	ResidentSize  uint64 // pti_resident_size — physical bytes resident
	VirtualSize   uint64 // pti_virtual_size — total address space mapped
	ThreadCount   uint32 // pti_threadnum
	FaultCount    uint32 // pti_faults — total minor + major faults
	PageinCount   uint32 // pti_pageins — major faults that required disk read
	CSwitches     uint32 // pti_csw — context switches (voluntary + involuntary)
	MessagesSent  uint32 // pti_messages_sent — Mach IPC sends
	MessagesRecvd uint32 // pti_messages_received
}

// ProcPidTaskInfo wraps proc_pidinfo(PROC_PIDTASKINFO). The pid must be
// owned by the current euid; otherwise the call returns EPERM.
func ProcPidTaskInfo(pid int) (LPTaskInfo, error) {
	var raw C.struct_proc_taskinfo
	var cerrno C.int
	n := C.wrap_proc_pidinfo(C.int(pid), C.PROC_PIDTASKINFO, 0,
		unsafe.Pointer(&raw), C.int(unsafe.Sizeof(raw)), &cerrno)
	if n <= 0 {
		return LPTaskInfo{}, fmt.Errorf("proc_pidinfo(PROC_PIDTASKINFO, %d): %w", pid, syscall.Errno(cerrno))
	}
	return LPTaskInfo{
		UserTimeNs:    uint64(C.mach_ticks_to_ns(C.uint64_t(raw.pti_total_user))),
		SystemTimeNs:  uint64(C.mach_ticks_to_ns(C.uint64_t(raw.pti_total_system))),
		ResidentSize:  uint64(raw.pti_resident_size),
		VirtualSize:   uint64(raw.pti_virtual_size),
		ThreadCount:   uint32(raw.pti_threadnum),
		FaultCount:    uint32(raw.pti_faults),
		PageinCount:   uint32(raw.pti_pageins),
		CSwitches:     uint32(raw.pti_csw),
		MessagesSent:  uint32(raw.pti_messages_sent),
		MessagesRecvd: uint32(raw.pti_messages_received),
	}, nil
}

// ─── Process name (proc_name) ────────────────────────────────────────────────

// ProcName returns the short executable name for pid (the kernel limits it
// to MAXCOMLEN, ~16 chars). Equivalent to /proc/<pid>/comm on Linux.
func ProcName(pid int) (string, error) {
	var buf [256]byte
	var cerrno C.int
	n := C.wrap_proc_name(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)), &cerrno)
	if n <= 0 {
		return "", fmt.Errorf("proc_name(%d): %w", pid, syscall.Errno(cerrno))
	}
	return string(buf[:n]), nil
}

// ─── RUsage (proc_pid_rusage) ────────────────────────────────────────────────

// LPRUsageInfo wraps the rusage_info_v4 fields the collectors actually use.
// Byte fields are cumulative since process start.
//
// We intentionally skip ri_user_time / ri_system_time: their units on
// Apple Silicon are ambiguous (headers claim nanoseconds, but observation
// shows mach_absolute_time-like values that need mach_timebase_info to
// convert). For CPU time use ProcPidTaskInfo — units are stable there
// (microseconds).
type LPRUsageInfo struct {
	DiskIOBytesRead  uint64 // ri_diskio_bytesread
	DiskIOBytesWrite uint64 // ri_diskio_byteswritten
	PageIns          uint64 // ri_pageins — major faults (RUSAGE counter)
	WiredSize        uint64 // ri_wired_size
	ResidentSize     uint64 // ri_resident_size
}

// ProcPidRUsage wraps proc_pid_rusage(RUSAGE_INFO_V4). v4 is universally
// available on supported macOS versions; we don't need v5/v6 fields yet.
func ProcPidRUsage(pid int) (LPRUsageInfo, error) {
	var raw C.struct_rusage_info_v4
	var cerrno C.int
	rc := C.wrap_proc_pid_rusage(C.int(pid), C.RUSAGE_INFO_V4,
		(*C.rusage_info_t)(unsafe.Pointer(&raw)), &cerrno)
	if rc != 0 {
		return LPRUsageInfo{}, fmt.Errorf("proc_pid_rusage(%d): %w", pid, syscall.Errno(cerrno))
	}
	return LPRUsageInfo{
		DiskIOBytesRead:  uint64(raw.ri_diskio_bytesread),
		DiskIOBytesWrite: uint64(raw.ri_diskio_byteswritten),
		PageIns:          uint64(raw.ri_pageins),
		WiredSize:        uint64(raw.ri_wired_size),
		ResidentSize:     uint64(raw.ri_resident_size),
	}, nil
}

// ─── Threads (PROC_PIDLISTTHREADS + PROC_PIDTHREADINFO) ──────────────────────

// ListThreads returns the Mach thread IDs of all threads in pid.
//
// The PROC_PIDLISTTHREADS flavor uses a two-call pattern: invoke once with a
// NULL buffer to learn the required size, then allocate and call again. We
// hedge: start with a buffer big enough for 64 threads, grow if needed.
func ListThreads(pid int) ([]uint64, error) {
	const tidSize = int(unsafe.Sizeof(uint64(0)))
	bufBytes := 64 * tidSize
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]uint64, bufBytes/tidSize)
		var cerrno C.int
		n := C.wrap_proc_pidinfo(C.int(pid), C.PROC_PIDLISTTHREADS, 0,
			unsafe.Pointer(&buf[0]), C.int(bufBytes), &cerrno)
		if n <= 0 {
			return nil, fmt.Errorf("proc_pidinfo(PROC_PIDLISTTHREADS, %d): %w", pid, syscall.Errno(cerrno))
		}
		// proc_pidinfo doesn't tell us "buffer was too small" — it just fills
		// what fits. Convention: if the returned size equals the buffer size,
		// retry with double the buffer.
		if int(n) == bufBytes {
			bufBytes *= 2
			continue
		}
		count := int(n) / tidSize
		return buf[:count], nil
	}
	return nil, errors.New("ListThreads: pid has more than 512 threads — buffer growth gave up")
}

// ThreadInfo is the per-thread snapshot from proc_pidinfo(PROC_PIDTHREADINFO).
// Times in MICROSECONDS, same as TaskInfo.
type LPThreadInfo struct {
	UserTimeNs   uint64 // pth_user_time, converted from mach ticks
	SystemTimeNs uint64 // pth_system_time, converted from mach ticks
	CPUUsage     int32  // 0..1000 (0.1% precision, as macOS reports it)
	Policy       int32  // POLICY_TIMESHARE=1, RR=2, FIFO=4
	RunState     int32  // TH_STATE_*
	Flags        int32  // TH_FLAGS_*
	SleepTime    uint32 // seconds blocked
	Name         string // pth_name, often empty
}

// ProcPidThreadInfo wraps proc_pidinfo(PROC_PIDTHREADINFO, tid). The tid must
// come from ListThreads on the same pid.
func ProcPidThreadInfo(pid int, tid uint64) (LPThreadInfo, error) {
	var raw C.struct_proc_threadinfo
	var cerrno C.int
	n := C.wrap_proc_pidinfo(C.int(pid), C.PROC_PIDTHREADINFO, C.uint64_t(tid),
		unsafe.Pointer(&raw), C.int(unsafe.Sizeof(raw)), &cerrno)
	if n <= 0 {
		return LPThreadInfo{}, fmt.Errorf("proc_pidinfo(PROC_PIDTHREADINFO, %d, %d): %w", pid, tid, syscall.Errno(cerrno))
	}
	name := C.GoString(&raw.pth_name[0])
	return LPThreadInfo{
		UserTimeNs:   uint64(C.mach_ticks_to_ns(C.uint64_t(raw.pth_user_time))),
		SystemTimeNs: uint64(C.mach_ticks_to_ns(C.uint64_t(raw.pth_system_time))),
		CPUUsage:     int32(raw.pth_cpu_usage),
		Policy:       int32(raw.pth_policy),
		RunState:     int32(raw.pth_run_state),
		Flags:        int32(raw.pth_flags),
		SleepTime:    uint32(raw.pth_sleep_time),
		Name:         name,
	}, nil
}

// Thread run states (from <mach/thread_info.h>).
const (
	ThreadStateRunning        = 1 // currently on CPU
	ThreadStateStopped        = 2
	ThreadStateWaiting        = 3 // blocked, interruptible
	ThreadStateUninterruptible = 4
	ThreadStateHalted         = 5
)

// ─── FD list (PROC_PIDLISTFDS) ───────────────────────────────────────────────

// FDType values come from <sys/proc_info.h> (PROX_FDTYPE_*).
const (
	FDTypeAtalk     = 0
	FDTypeVNode     = 1 // file or directory
	FDTypeSocket    = 2
	FDTypePSHM      = 3 // POSIX shared memory
	FDTypePSEM      = 4 // POSIX semaphore
	FDTypeKQueue    = 5
	FDTypePipe      = 6
	FDTypeFSEvents  = 7
	FDTypeNetPolicy = 9
)

// FDInfo is a (fd, type) pair from PROC_PIDLISTFDS. To get the type-specific
// details, follow up with one of the FDxxx wrappers below.
type LPFDInfo struct {
	FD   int32
	Type int32
}

// ListFDs returns the FDs open in pid. Same growth pattern as ListThreads.
func ListFDs(pid int) ([]LPFDInfo, error) {
	const recSize = int(unsafe.Sizeof(C.struct_proc_fdinfo{}))
	bufBytes := 128 * recSize
	for attempt := 0; attempt < 5; attempt++ {
		buf := make([]C.struct_proc_fdinfo, bufBytes/recSize)
		var cerrno C.int
		n := C.wrap_proc_pidinfo(C.int(pid), C.PROC_PIDLISTFDS, 0,
			unsafe.Pointer(&buf[0]), C.int(bufBytes), &cerrno)
		if n <= 0 {
			return nil, fmt.Errorf("proc_pidinfo(PROC_PIDLISTFDS, %d): %w", pid, syscall.Errno(cerrno))
		}
		if int(n) == bufBytes {
			bufBytes *= 2
			continue
		}
		count := int(n) / recSize
		out := make([]LPFDInfo, count)
		for i := 0; i < count; i++ {
			out[i] = LPFDInfo{
				FD:   int32(buf[i].proc_fd),
				Type: int32(buf[i].proc_fdtype),
			}
		}
		return out, nil
	}
	return nil, errors.New("ListFDs: pid has more than 2048 FDs — buffer growth gave up")
}

// ─── FD detail: vnode (file/dir) ─────────────────────────────────────────────

// VNodeFDInfo is the result of proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO).
type LPVNodeFDInfo struct {
	Path  string
	VType int32 // VREG=1, VDIR=2, VCHR=3, VBLK=4, VLNK=5, VSOCK=6, VFIFO=7
}

func FDVNodePath(pid int, fd int32) (LPVNodeFDInfo, error) {
	var raw C.struct_vnode_fdinfowithpath
	var cerrno C.int
	n := C.wrap_proc_pidfdinfo(C.int(pid), C.int(fd), C.PROC_PIDFDVNODEPATHINFO,
		unsafe.Pointer(&raw), C.int(unsafe.Sizeof(raw)), &cerrno)
	if n <= 0 {
		return LPVNodeFDInfo{}, fmt.Errorf("proc_pidfdinfo(VNODEPATHINFO, %d, %d): %w", pid, fd, syscall.Errno(cerrno))
	}
	return LPVNodeFDInfo{
		Path:  C.GoString(&raw.pvip.vip_path[0]),
		VType: int32(raw.pvip.vip_vi.vi_stat.vst_mode),
	}, nil
}

// ─── FD detail: pipe ─────────────────────────────────────────────────────────

// PipeFDInfo is the result of proc_pidfdinfo(PROC_PIDFDPIPEINFO).
type LPPipeFDInfo struct {
	PipeID uint64
	Status uint32
}

func FDPipeInfo(pid int, fd int32) (LPPipeFDInfo, error) {
	var raw C.struct_pipe_fdinfo
	var cerrno C.int
	n := C.wrap_proc_pidfdinfo(C.int(pid), C.int(fd), C.PROC_PIDFDPIPEINFO,
		unsafe.Pointer(&raw), C.int(unsafe.Sizeof(raw)), &cerrno)
	if n <= 0 {
		return LPPipeFDInfo{}, fmt.Errorf("proc_pidfdinfo(PIPEINFO, %d, %d): %w", pid, fd, syscall.Errno(cerrno))
	}
	return LPPipeFDInfo{
		PipeID: uint64(raw.pipeinfo.pipe_handle),
		Status: uint32(raw.pipeinfo.pipe_status),
	}, nil
}

// ─── FD detail: socket ───────────────────────────────────────────────────────

// LPSocketFDInfo is the result of proc_pidfdinfo(PROC_PIDFDSOCKETINFO).
// For TCP/UDP, LocalAddr and RemoteAddr are populated as "host:port" strings.
// For UNIX domain sockets, the path lives in LocalAddr.
type LPSocketFDInfo struct {
	Family     int32  // AF_INET=2, AF_INET6=30, AF_UNIX=1
	SockType   int32  // SOCK_STREAM=1, SOCK_DGRAM=2
	Protocol   int32  // IPPROTO_TCP=6, IPPROTO_UDP=17
	TCPState   int32  // 0=CLOSED, 1=LISTEN, 2=SYN_SENT, 4=ESTABLISHED, etc — only valid when SockType=STREAM
	LocalAddr  string
	RemoteAddr string
}

// TCP states (from <netinet/tcp_fsm.h>).
const (
	TCPStateClosed      = 0
	TCPStateListen      = 1
	TCPStateSynSent     = 2
	TCPStateSynReceived = 3
	TCPStateEstablished = 4
	TCPStateCloseWait   = 5
	TCPStateFinWait1    = 6
	TCPStateClosing     = 7
	TCPStateLastAck     = 8
	TCPStateFinWait2    = 9
	TCPStateTimeWait    = 10
)

func FDSocketInfo(pid int, fd int32) (LPSocketFDInfo, error) {
	var raw C.struct_socket_fdinfo
	var cerrno C.int
	n := C.wrap_proc_pidfdinfo(C.int(pid), C.int(fd), C.PROC_PIDFDSOCKETINFO,
		unsafe.Pointer(&raw), C.int(unsafe.Sizeof(raw)), &cerrno)
	if n <= 0 {
		return LPSocketFDInfo{}, fmt.Errorf("proc_pidfdinfo(SOCKETINFO, %d, %d): %w", pid, fd, syscall.Errno(cerrno))
	}

	out := LPSocketFDInfo{
		Family:   int32(raw.psi.soi_family),
		SockType: int32(raw.psi.soi_type),
		Protocol: int32(raw.psi.soi_protocol),
	}

	// soi_proto is a union of in_sockinfo / un_sockinfo / tcp_sockinfo / ...
	// cgo exposes it as opaque bytes; cast its address to the right view.
	protoPtr := unsafe.Pointer(&raw.psi.soi_proto)

	switch out.Family {
	case C.AF_INET:
		ipi := (*C.struct_in_sockinfo)(protoPtr)
		// in4in6_addr_t is a union ([16]byte in cgo). For an AF_INET socket,
		// the v4 address lives in the last 4 bytes (the i46a_addr4 member of
		// the ina_46 sub-struct, after 12 bytes of pad).
		lport := int(ntohs(uint16(ipi.insi_lport)))
		fport := int(ntohs(uint16(ipi.insi_fport)))
		out.LocalAddr = fmtV4(addrV4(&ipi.insi_laddr), lport)
		out.RemoteAddr = fmtV4(addrV4(&ipi.insi_faddr), fport)
		if out.SockType == C.SOCK_STREAM {
			tcp := (*C.struct_tcp_sockinfo)(protoPtr)
			out.TCPState = int32(tcp.tcpsi_state)
		}
	case C.AF_INET6:
		ipi := (*C.struct_in_sockinfo)(protoPtr)
		lport := int(ntohs(uint16(ipi.insi_lport)))
		fport := int(ntohs(uint16(ipi.insi_fport)))
		out.LocalAddr = fmtV6(addrV6(&ipi.insi_laddr), lport)
		out.RemoteAddr = fmtV6(addrV6(&ipi.insi_faddr), fport)
		if out.SockType == C.SOCK_STREAM {
			tcp := (*C.struct_tcp_sockinfo)(protoPtr)
			out.TCPState = int32(tcp.tcpsi_state)
		}
	case C.AF_UNIX:
		// un_sockinfo.unsi_addr is a union starting with sockaddr_un, whose
		// sun_path begins at offset 2 (sun_len: u8, sun_family: u8, then path).
		un := (*C.struct_un_sockinfo)(protoPtr)
		out.LocalAddr = unixPath(unsafe.Pointer(&un.unsi_addr))
	}
	return out, nil
}

// addrV4 returns a pointer to the embedded struct in_addr inside an
// in4in6_addr_t union. The union is laid out as 12 pad bytes followed by the
// 4-byte v4 address. We work directly on raw bytes because cgo exposes the
// union as [16]byte, not as the named ina_46 member.
func addrV4(u *[16]byte) *C.struct_in_addr {
	return (*C.struct_in_addr)(unsafe.Pointer(&u[12]))
}

// addrV6 returns a pointer to the embedded struct in6_addr inside an
// in4in6_addr_t union. For v6 the full 16 bytes are the address.
func addrV6(u *[16]byte) *C.struct_in6_addr {
	return (*C.struct_in6_addr)(unsafe.Pointer(&u[0]))
}

// unixPath extracts sun_path from a un_sockinfo.unsi_addr union view. The
// path starts at byte offset 2 (after sun_len + sun_family) and is up to 104
// bytes including NUL terminator.
func unixPath(u unsafe.Pointer) string {
	const sunPathOffset = 2
	return C.GoString((*C.char)(unsafe.Pointer(uintptr(u) + sunPathOffset)))
}

// fmtV4 formats a struct in_addr as "1.2.3.4:port".
func fmtV4(a *C.struct_in_addr, port int) string {
	buf := make([]byte, C.INET_ADDRSTRLEN)
	n := C.fmt_v4(a, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n < 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", string(buf[:n]), port)
}

// fmtV6 formats a struct in6_addr as "[::1]:port".
func fmtV6(a *C.struct_in6_addr, port int) string {
	buf := make([]byte, C.INET6_ADDRSTRLEN)
	n := C.fmt_v6(a, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n < 0 {
		return ""
	}
	return fmt.Sprintf("[%s]:%d", string(buf[:n]), port)
}

// ntohs converts network-order uint16 to host order. Mac is little-endian on
// both x86_64 and arm64, so we just byte-swap unconditionally.
func ntohs(n uint16) uint16 { return (n>>8)&0xff | (n&0xff)<<8 }
