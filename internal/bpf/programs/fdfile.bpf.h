/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fdfile.bpf.h — the file behind one of the current task's fds, read through
 * the task's fd table: task → files → fdt → fd[n].
 *
 * Shared by the syscalls axis, which classifies the fd a read or write hit by
 * its inode type (#176), and the io axis, which identifies the file by its
 * inode number so the collector can name it as it was when the call ran
 * rather than when the event is processed (#162).
 *
 * The kernel structs are declared to the depth needed and relocated by CO-RE,
 * the same way network.bpf.c reads a socket: no vmlinux.h. CO-RE relocates
 * only the fields a program reads, so a field one program needs costs the
 * other nothing.
 */
#ifndef PTOP_FDFILE_BPF_H
#define PTOP_FDFILE_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct inode___ptop {
    unsigned short i_mode;
    unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file___ptop {
    struct inode___ptop *f_inode;
} __attribute__((preserve_access_index));

struct fdtable___ptop {
    unsigned int max_fds;
    struct file___ptop **fd;
} __attribute__((preserve_access_index));

struct files_struct___ptop {
    struct fdtable___ptop *fdt;
} __attribute__((preserve_access_index));

struct task_struct___ptop {
    struct files_struct___ptop *files;
} __attribute__((preserve_access_index));

/* fd_file returns the file the current task holds at fd, or 0 when the fd is
 * out of range, closed, or the table could not be read. */
static __always_inline struct file___ptop *fd_file(long fd)
{
    struct task_struct___ptop *task = (void *)bpf_get_current_task();
    struct files_struct___ptop *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;
    struct fdtable___ptop *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return 0;
    unsigned int max = BPF_CORE_READ(fdt, max_fds);
    if (fd < 0 || fd >= max)
        return 0;
    struct file___ptop **fds = BPF_CORE_READ(fdt, fd);
    struct file___ptop *f = 0;
    if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) != 0)
        return 0;
    return f;
}

/* fd_ino is the inode number of the file at fd — what /proc/<pid>/fdinfo/<fd>
 * prints as `ino:` — or 0 when there is none to read. */
static __always_inline __u64 fd_ino(long fd)
{
    struct file___ptop *f = fd_file(fd);
    if (!f)
        return 0;
    return BPF_CORE_READ(f, f_inode, i_ino);
}

#endif /* PTOP_FDFILE_BPF_H */
