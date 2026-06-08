package collector

import "testing"

func TestParseNSInode(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"pid:[4026531836]", 4026531836},
		{"net:[4026532008]", 4026532008},
		{"mnt:[4026531840]", 4026531840},
		{"", 0},
		{"pid:[]", 0},
		{"pid:4026531836", 0}, // no brackets
		{"pid:[notanumber]", 0},
		{"cgroup:[4026531835]", 4026531835},
	}
	for _, c := range cases {
		if got := parseNSInode(c.in); got != c.want {
			t.Errorf("parseNSInode(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseCgroup(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "v2 unified",
			in:   "0::/system.slice/docker-abc.scope\n",
			want: "/system.slice/docker-abc.scope",
		},
		{
			name: "v1 multiple, prefer unified",
			in: "12:pids:/docker/abc\n" +
				"11:hugetlb:/docker/abc\n" +
				"0::/docker/abc\n",
			want: "/docker/abc",
		},
		{
			name: "v1 only, first line fallback",
			in:   "12:pids:/docker/abc\n11:memory:/docker/abc\n",
			want: "/docker/abc",
		},
		{
			name: "root cgroup",
			in:   "0::/\n",
			want: "/",
		},
		{
			name: "path with colon",
			in:   "0::/weird:path/here\n",
			want: "/weird:path/here",
		},
		{name: "empty", in: "", want: ""},
		{name: "garbage", in: "not-a-cgroup-line\n", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseCgroup(c.in); got != c.want {
				t.Errorf("parseCgroup() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDeriveContainer(t *testing.T) {
	const cid = "ab12cd34ef5678901234567890123456789012345678901234567890abcdef00"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "docker cgroupfs driver",
			in:   "/docker/" + cid,
			want: "docker:ab12cd34ef56",
		},
		{
			name: "docker systemd driver",
			in:   "/system.slice/docker-" + cid + ".scope",
			want: "docker:ab12cd34ef56",
		},
		{
			name: "kubepods cri-containerd",
			in:   "/kubepods/besteffort/pod1234abcd-5678-90ef/cri-containerd-" + cid + ".scope",
			want: "containerd:ab12cd34ef56",
		},
		{
			name: "kubepods generic",
			in:   "/kubepods/burstable/podaaaa-bbbb/" + cid,
			want: "kubepods:ab12cd34ef56",
		},
		{
			name: "libpod / podman",
			in:   "/machine.slice/libpod-" + cid + ".scope",
			want: "libpod:ab12cd34ef56",
		},
		{
			name: "crio",
			in:   "/kubepods/pod-x/crio-" + cid + ".scope",
			want: "crio:ab12cd34ef56",
		},
		{
			name: "lxc path form",
			in:   "/lxc/mycontainer/init.scope",
			want: "lxc:mycontainer",
		},
		{
			name: "lxc payload form",
			in:   "/lxc.payload.web01/system.slice",
			want: "lxc:web01",
		},
		{
			name: "bare hex leaf",
			in:   "/" + cid,
			want: "container:ab12cd34ef56",
		},
		{
			name: "host root — no container",
			in:   "/",
			want: "",
		},
		{
			name: "host systemd unit — no container",
			in:   "/system.slice/sshd.service",
			want: "",
		},
		{name: "empty", in: "", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deriveContainer(c.in); got != c.want {
				t.Errorf("deriveContainer(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestParseStatusUIDGID(t *testing.T) {
	status := "Name:\tbash\n" +
		"Umask:\t0022\n" +
		"State:\tS (sleeping)\n" +
		"Uid:\t1000\t1000\t1000\t1000\n" +
		"Gid:\t1001\t1001\t1001\t1001\n" +
		"FDSize:\t256\n"
	uid, gid := parseStatusUIDGID(status)
	if uid != 1000 {
		t.Errorf("uid = %d, want 1000", uid)
	}
	if gid != 1001 {
		t.Errorf("gid = %d, want 1001", gid)
	}

	// Root and absent lines.
	uid, gid = parseStatusUIDGID("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
	if uid != 0 || gid != 0 {
		t.Errorf("root uid/gid = %d/%d, want 0/0", uid, gid)
	}
	uid, gid = parseStatusUIDGID("Name:\tx\n")
	if uid != 0 || gid != 0 {
		t.Errorf("missing uid/gid = %d/%d, want 0/0", uid, gid)
	}
}
