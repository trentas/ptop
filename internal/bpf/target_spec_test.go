package bpf

import (
	"strings"
	"testing"
	"testing/fstest"
)

// Real-shaped mountinfo: a modern unified-only host, a hybrid host where the
// v2 hierarchy hangs off /sys/fs/cgroup/unified, and a v1-only host.
const (
	mountinfoV2 = `23 28 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
25 23 0:24 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:8 - bpf bpf rw,mode=700
30 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
`
	mountinfoHybrid = `30 23 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
31 30 0:27 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate
32 30 0:28 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd
33 30 0:29 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:12 - cgroup cgroup rw,memory
`
	mountinfoV1 = `30 23 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
32 30 0:28 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd
`
	// The kernel escapes the characters that would break field separation.
	mountinfoEscaped = `30 23 0:26 / /mnt/my\040cgroups rw,relatime shared:9 - cgroup2 cgroup2 rw
`
)

func TestCgroup2Root(t *testing.T) {
	cases := []struct {
		name, mountinfo, want, wantErr string
	}{
		{name: "unified only", mountinfo: mountinfoV2, want: "/sys/fs/cgroup"},
		{name: "hybrid picks the v2 mount", mountinfo: mountinfoHybrid, want: "/sys/fs/cgroup/unified"},
		{name: "v1 only", mountinfo: mountinfoV1, wantErr: "needs cgroup v2"},
		{name: "empty", mountinfo: "", wantErr: "needs cgroup v2"},
		{name: "escaped mount point", mountinfo: mountinfoEscaped, want: "/mnt/my cgroups"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cgroup2Root(tc.mountinfo)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("cgroup2Root = %q, want error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("cgroup2Root: %v", err)
			}
			if got != tc.want {
				t.Errorf("cgroup2Root = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCgroupLevel(t *testing.T) {
	const root = "/sys/fs/cgroup"
	cases := []struct {
		target  string
		want    uint32
		wantErr bool
	}{
		{target: "/sys/fs/cgroup", want: 0},
		{target: "/sys/fs/cgroup/", want: 0},
		{target: "/sys/fs/cgroup/system.slice", want: 1},
		{target: "/sys/fs/cgroup/system.slice/docker.service", want: 2},
		{target: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/pod.slice/ctr.scope", want: 4},
		// Not under the root at all.
		{target: "/sys/fs/cgroup-other/x", wantErr: true},
		{target: "/etc/passwd", wantErr: true},
	}
	for _, tc := range cases {
		got, err := cgroupLevel(root, tc.target)
		if tc.wantErr {
			if err == nil {
				t.Errorf("cgroupLevel(%q) = %d, want error", tc.target, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("cgroupLevel(%q): %v", tc.target, err)
			continue
		}
		if got != tc.want {
			t.Errorf("cgroupLevel(%q) = %d, want %d", tc.target, got, tc.want)
		}
	}
}

// kubepodsFS is the shape a Kubernetes node's cgroup tree actually has:
// kubepods.slice → QoS slice → pod slice → one scope per container.
func kubepodsFS() fstest.MapFS {
	f := &fstest.MapFile{}
	return fstest.MapFS{
		"cgroup.procs": f,
		"system.slice/containerd.service/cgroup.procs": f,
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf00d.slice/cri-containerd-abc123def456789.scope/cgroup.procs":  f,
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf00d.slice/cri-containerd-beef987654321.scope/cgroup.procs":    f,
		"kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podcafe.slice/cri-containerd-abc123ffffffff.scope/cgroup.procs": f,
	}
}

func TestFindCgroup(t *testing.T) {
	fsys := kubepodsFS()

	t.Run("unique container id", func(t *testing.T) {
		got, err := findCgroup(fsys, "abc123def456789")
		if err != nil {
			t.Fatalf("findCgroup: %v", err)
		}
		const want = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf00d.slice/cri-containerd-abc123def456789.scope"
		if got != want {
			t.Errorf("findCgroup = %q, want %q", got, want)
		}
	})

	t.Run("pod slice matches its own directory", func(t *testing.T) {
		got, err := findCgroup(fsys, "podf00d")
		if err != nil {
			t.Fatalf("findCgroup: %v", err)
		}
		if got != "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf00d.slice" {
			t.Errorf("findCgroup = %q, want the pod slice", got)
		}
	})

	t.Run("no match", func(t *testing.T) {
		if got, err := findCgroup(fsys, "0000000000"); err == nil {
			t.Errorf("findCgroup = %q, want an error", got)
		}
	})

	// A short id shared by two containers must not silently pick one: attaching
	// the tracers to the wrong workload is worse than refusing.
	t.Run("ambiguous prefix", func(t *testing.T) {
		got, err := findCgroup(fsys, "abc123")
		if err == nil {
			t.Fatalf("findCgroup = %q, want an ambiguity error", got)
		}
		if !strings.Contains(err.Error(), "matches 2 cgroups") {
			t.Errorf("error = %q, want it to report the ambiguity", err)
		}
	})

	t.Run("deeper than the search bound", func(t *testing.T) {
		deep := fstest.MapFS{
			"a/b/c/d/e/f/g/h/i/needle-here/cgroup.procs": &fstest.MapFile{},
		}
		if got, err := findCgroup(deep, "needle-here"); err == nil {
			t.Errorf("findCgroup = %q, want the depth bound to stop the walk", got)
		}
	})
}

func TestCgroupPath(t *testing.T) {
	fsys := kubepodsFS()
	const root = "/sys/fs/cgroup"

	cases := []struct {
		name, spec, want, wantErr string
	}{
		{
			name: "absolute host path passes through",
			spec: "/sys/fs/cgroup/system.slice/containerd.service",
			want: "/sys/fs/cgroup/system.slice/containerd.service",
		},
		{
			// The form /proc/<pid>/cgroup prints.
			name: "root-relative path is joined",
			spec: "/kubepods.slice/kubepods-burstable.slice",
			want: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice",
		},
		{
			name: "container id is looked up",
			spec: "beef987654321",
			want: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf00d.slice/cri-containerd-beef987654321.scope",
		},
		{name: "empty spec", spec: "", wantErr: "empty cgroup spec"},
		{name: "unknown id", spec: "nosuchcontainer", wantErr: "no cgroup matches"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cgroupPath(fsys, root, tc.spec)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("cgroupPath = %q, want error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("cgroupPath: %v", err)
			}
			if got != tc.want {
				t.Errorf("cgroupPath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTargetSpec(t *testing.T) {
	pid := TargetPID(4242)
	if pid.IsCgroup() {
		t.Error("TargetPID reports cgroup mode")
	}
	if err := pid.validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
	if got := pid.String(); got != "pid 4242" {
		t.Errorf("String = %q", got)
	}

	cg := TargetCgroup("/kubepods.slice/x.scope")
	if !cg.IsCgroup() {
		t.Error("TargetCgroup does not report cgroup mode")
	}
	if err := cg.validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
	if got := cg.String(); got != "cgroup /kubepods.slice/x.scope" {
		t.Errorf("String = %q", got)
	}

	// A pid target still has to name a process; a cgroup target never needs one.
	if err := (Target{}).validate(); err == nil {
		t.Error("the zero Target validated")
	}
}
