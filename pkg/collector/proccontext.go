package collector

import (
	"strconv"
	"strings"
)

// Parsers for the execution-context collector (#60). Kept build-tag-free (no
// linux/ebpf gate) so they compile and are unit-tested on any OS — the same
// split fs_decode.go / signal_decode.go use. The OS-specific /proc reading
// lives in proccontext_linux.go.

// parseNSInode extracts the inode from a namespace symlink target of the form
// "pid:[4026531836]" (what readlink(/proc/<pid>/ns/<kind>) returns). Returns 0
// when the form isn't recognized.
func parseNSInode(link string) uint64 {
	open := strings.IndexByte(link, '[')
	close := strings.IndexByte(link, ']')
	if open < 0 || close < 0 || close <= open+1 {
		return 0
	}
	n, err := strconv.ParseUint(link[open+1:close], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// parseCgroup picks the target's cgroup path from the contents of
// /proc/<pid>/cgroup. Each line is "hierarchy-ID:controller-list:path". The
// cgroup-v2 unified line has an empty controller list ("0::/path") and is
// preferred; otherwise the first line's path is returned. Returns "" when the
// data has no usable line.
func parseCgroup(data string) string {
	var fallback string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// SplitN with 3 so a ':' inside the path (rare) stays intact.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		controllers, path := parts[1], parts[2]
		if controllers == "" { // cgroup v2 unified hierarchy
			return path
		}
		if fallback == "" {
			fallback = path
		}
	}
	return fallback
}

// deriveContainer turns a cgroup path into a best-effort container id like
// "docker:ab12cd34ef56", classifying the runtime by keyword and using the
// 64-hex container id (truncated to 12) found in the path. LXC payloads carry a
// name rather than a hex id, so the trailing path segment is used. Returns ""
// when the path isn't from a recognized container runtime.
func deriveContainer(cgroupPath string) string {
	if cgroupPath == "" {
		return ""
	}
	lower := strings.ToLower(cgroupPath)
	id := shortHex(longestHexRun(lower, 32))

	switch {
	case strings.Contains(lower, "lxc"):
		// "/lxc/<name>" or "lxc.payload.<name>" — the name isn't hex.
		if name := lxcName(cgroupPath); name != "" {
			return "lxc:" + name
		}
		return "lxc"
	case strings.Contains(lower, "libpod"):
		return withID("libpod", id)
	case strings.Contains(lower, "cri-containerd") || strings.Contains(lower, "containerd"):
		return withID("containerd", id)
	case strings.Contains(lower, "crio") || strings.Contains(lower, "cri-o"):
		return withID("crio", id)
	case strings.Contains(lower, "docker"):
		return withID("docker", id)
	case strings.Contains(lower, "kubepods"):
		// Generic Kubernetes pod with no embedded runtime keyword.
		return withID("kubepods", id)
	default:
		// No runtime keyword, but a bare 64-hex leaf is still very likely a
		// container (some setups mount the container cgroup directly).
		if id != "" && looksLikeContainerLeaf(lower) {
			return "container:" + id
		}
		return ""
	}
}

// withID joins a runtime label with its container id, dropping the id when none
// was found (e.g. the path named the runtime but carried no hex id).
func withID(label, id string) string {
	if id == "" {
		return label
	}
	return label + ":" + id
}

// shortHex truncates a container id to its first 12 chars (the conventional
// "docker ps" short id). Returns "" unchanged.
func shortHex(hex string) string {
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// longestHexRun returns the longest run of lowercase-hex digits in s with
// length >= min, or "" if none qualifies. Container ids are 64-hex, so this
// reliably skips the hyphenated pod UUIDs and short hierarchy numbers.
func longestHexRun(s string, min int) string {
	best, bestLen := "", 0
	i := 0
	for i < len(s) {
		if isHex(s[i]) {
			j := i
			for j < len(s) && isHex(s[j]) {
				j++
			}
			if j-i > bestLen {
				best, bestLen = s[i:j], j-i
			}
			i = j
		} else {
			i++
		}
	}
	if bestLen >= min {
		return best
	}
	return ""
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// looksLikeContainerLeaf reports whether the path's final segment is a long hex
// blob (>=32 chars, optionally with a .scope/.slice systemd suffix), the shape
// of a directly-mounted container cgroup.
func looksLikeContainerLeaf(lower string) bool {
	seg := lower
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	seg = strings.TrimSuffix(seg, ".scope")
	seg = strings.TrimSuffix(seg, ".slice")
	// Strip a leading "<runtime>-" prefix (systemd cgroup driver form).
	if i := strings.LastIndexByte(seg, '-'); i >= 0 && i+1 < len(seg) {
		seg = seg[i+1:]
	}
	return len(seg) >= 32 && longestHexRun(seg, 32) == seg
}

// lxcName extracts the LXC container name from "/lxc/<name>/..." or
// "lxc.payload.<name>" forms. Returns "" when no name segment follows.
func lxcName(cgroupPath string) string {
	for _, seg := range strings.Split(cgroupPath, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(seg, "lxc.payload."); ok {
			return rest
		}
		if seg == "lxc" {
			continue
		}
		// First non-"lxc" segment after we've seen the lxc keyword.
		if strings.Contains(cgroupPath, "/lxc/") {
			if i := strings.Index(cgroupPath, "/lxc/"); i >= 0 {
				rest := cgroupPath[i+len("/lxc/"):]
				if j := strings.IndexByte(rest, '/'); j >= 0 {
					return rest[:j]
				}
				return rest
			}
		}
	}
	return ""
}

// parseStatusUIDGID reads the real UID and GID from the contents of
// /proc/<pid>/status. The "Uid:"/"Gid:" lines list real, effective, saved, and
// fs ids; the first (real) is the conventional process owner. Returns (0, 0)
// when the lines are absent.
func parseStatusUIDGID(status string) (uid, gid uint32) {
	for _, line := range strings.Split(status, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			uid = firstUint32(rest)
		} else if rest, ok := strings.CutPrefix(line, "Gid:"); ok {
			gid = firstUint32(rest)
		}
	}
	return uid, gid
}

// firstUint32 parses the first whitespace-separated field of s as a uint32,
// returning 0 on failure.
func firstUint32(s string) uint32 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	n, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
