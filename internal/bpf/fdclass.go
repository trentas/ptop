package bpf

// FdClassName names the class of fd a read or write hit, as syscalls.bpf.c
// encodes it (FD_CLASS_*, #176). An anonymous inode is an eventfd, epoll,
// timerfd or signalfd: on a Go target, the runtime's netpoller waking itself.
func FdClassName(c uint32) string {
	switch c {
	case 1:
		return "anon"
	case 2:
		return "socket"
	case 3:
		return "pipe"
	case 4:
		return "file"
	case 5:
		return "char"
	case 6:
		return "other"
	default:
		return "unknown"
	}
}
