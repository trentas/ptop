//go:build darwin

package mcp

import "golang.org/x/sys/unix"

// processUIDs reads the real, effective and saved uids of pid from the
// kernel's process table. macOS has no filesystem uid.
func processUIDs(pid int) ([]uint32, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return nil, err
	}
	return []uint32{kp.Eproc.Pcred.P_ruid, kp.Eproc.Ucred.Uid, kp.Eproc.Pcred.P_svuid}, nil
}
