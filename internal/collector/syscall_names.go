package collector

import "fmt"

// syscallName resolve syscall_id → nome legível. Tabela é arch-específica em
// Linux: aarch64 e amd64 mapeiam números diferentes pros mesmos syscalls.
//
// Aqui uso uma tabela curada com os ~50 mais comuns que aparecem em qualquer
// processo userspace típico — o que vai dominar o top-N do mockup. Syscalls
// não listados retornam "syscall_<id>".
//
// Fontes:
//   - aarch64: arch/arm64/include/uapi/asm/unistd.h + asm-generic
//   - amd64:   arch/x86/entry/syscalls/syscall_64.tbl
//
// Mantido manualmente em vez de gerado de /usr/include/asm/unistd_64.h
// pra evitar build-time deps em libc headers.

func syscallName(id uint32, isARM64 bool) string {
	var table map[uint32]string
	if isARM64 {
		table = syscallsARM64
	} else {
		table = syscallsAMD64
	}
	if name, ok := table[id]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", id)
}

// AArch64 (arm64) usa tabela "asm-generic" — mesma do RISC-V.
// Numbers em arch/arm64/include/uapi/asm/unistd.h.
var syscallsARM64 = map[uint32]string{
	17:  "getcwd",
	19:  "eventfd2",
	20:  "epoll_create1",
	21:  "epoll_ctl",
	22:  "epoll_pwait",
	23:  "dup",
	24:  "dup3",
	25:  "fcntl",
	29:  "ioctl",
	32:  "flock",
	38:  "renameat",
	40:  "mount",
	48:  "faccessat",
	49:  "chdir",
	53:  "fchmodat",
	56:  "openat",
	57:  "close",
	59:  "pipe2",
	61:  "getdents64",
	62:  "lseek",
	63:  "read",
	64:  "write",
	65:  "readv",
	66:  "writev",
	67:  "pread64",
	68:  "pwrite64",
	72:  "pselect6",
	73:  "ppoll",
	78:  "readlinkat",
	79:  "fstatat",
	80:  "fstat",
	82:  "fsync",
	83:  "fdatasync",
	93:  "exit",
	94:  "exit_group",
	98:  "futex",
	101: "nanosleep",
	113: "clock_gettime",
	115: "clock_nanosleep",
	124: "sched_yield",
	131: "tgkill",
	134: "rt_sigaction",
	135: "rt_sigprocmask",
	139: "rt_sigreturn",
	160: "uname",
	172: "getpid",
	173: "getppid",
	174: "getuid",
	175: "geteuid",
	176: "getgid",
	178: "gettid",
	200: "bind",
	202: "accept",
	203: "connect",
	206: "sendto",
	207: "recvfrom",
	208: "setsockopt",
	209: "getsockopt",
	214: "brk",
	215: "munmap",
	216: "mremap",
	220: "clone",
	221: "execve",
	222: "mmap",
	226: "mprotect",
	233: "madvise",
	242: "accept4",
	260: "wait4",
	281: "execveat",
	283: "membarrier",
	291: "statx",
}

// AMD64 (x86_64) — números em arch/x86/entry/syscalls/syscall_64.tbl.
var syscallsAMD64 = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	28:  "madvise",
	32:  "dup",
	33:  "dup2",
	35:  "nanosleep",
	39:  "getpid",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	49:  "bind",
	50:  "listen",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	83:  "mkdir",
	86:  "link",
	87:  "unlink",
	89:  "readlink",
	102: "getuid",
	104: "getgid",
	107: "geteuid",
	108: "getegid",
	110: "getppid",
	186: "gettid",
	202: "futex",
	217: "getdents64",
	228: "clock_gettime",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	233: "epoll_ctl",
	257: "openat",
	262: "newfstatat",
	273: "set_robust_list",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	302: "prlimit64",
	318: "getrandom",
	332: "statx",
	334: "rseq",
	435: "clone3",
}
