package serve

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// handshakeFor starts a server for target and returns the TargetInfo the first
// response carries.
func handshakeFor(t *testing.T, target Target) *pb.TargetInfo {
	t.Helper()
	sock := shortSock(t)
	addr := "unix://" + sock

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFake(4)
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, addr, target, &collector.Feed{Bus: collector.StartBus(ctx, []collector.Collector{f})}, nil, Options{})
	}()
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	recvCtx, recvCancel := context.WithTimeout(ctx, 3*time.Second)
	defer recvCancel()
	stream, err := pb.NewEventStreamServiceClient(conn).Subscribe(recvCtx, &pb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	ti := resp.GetMeta().GetTarget()
	if ti == nil {
		t.Fatalf("first response carries no TargetInfo: %v", resp)
	}

	cancel()
	<-runErr
	return ti
}

// Every subscriber is told the scope of the stream before it sees an event —
// in cgroup mode that is the only way to know events are subtree-wide and
// carry no single pid.
func TestSubscribeHandshakeDeclaresTarget(t *testing.T) {
	t.Run("pid mode", func(t *testing.T) {
		ti := handshakeFor(t, TargetPID(4242))
		if ti.GetMode() != pb.TargetMode_TARGET_MODE_PID {
			t.Errorf("mode = %v, want PID", ti.GetMode())
		}
		if ti.GetPid() != 4242 {
			t.Errorf("pid = %d, want 4242", ti.GetPid())
		}
		if ti.GetCgroupPath() != "" || ti.GetCgroupId() != 0 {
			t.Errorf("cgroup fields set in pid mode: %v", ti)
		}
	})

	t.Run("cgroup mode", func(t *testing.T) {
		const path = "/sys/fs/cgroup/kubepods.slice/pod.slice/ctr.scope"
		ti := handshakeFor(t, TargetCgroup(path, 4026532))
		if ti.GetMode() != pb.TargetMode_TARGET_MODE_CGROUP {
			t.Errorf("mode = %v, want CGROUP", ti.GetMode())
		}
		if ti.GetCgroupPath() != path {
			t.Errorf("cgroup_path = %q, want %q", ti.GetCgroupPath(), path)
		}
		if ti.GetCgroupId() != 4026532 {
			t.Errorf("cgroup_id = %d, want 4026532", ti.GetCgroupId())
		}
		// No pid to report: the subtree is the target.
		if ti.GetPid() != 0 {
			t.Errorf("pid = %d, want 0 in cgroup mode", ti.GetPid())
		}
	})
}

// In cgroup mode the envelope pid stays 0: events come from anywhere in the
// subtree, so stamping one process's pid on them would be a lie.
func TestCgroupModeLeavesEnvelopePidUnset(t *testing.T) {
	h := NewHub(TargetCgroup("/sys/fs/cgroup/x.scope", 7), "", nil)
	ev := h.targetInfo()
	if ev.GetPid() != 0 {
		t.Fatalf("handshake pid = %d, want 0", ev.GetPid())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newFake(4)
	sub := h.subscribe(nil)
	h.Start(ctx, collector.StartBus(ctx, []collector.Collector{f}))
	f.ch <- collector.CpuSample{UsagePct: 5, Timestamp: time.Now()}

	select {
	case resp := <-sub.ch:
		if got := resp.GetEvent().GetPid(); got != 0 {
			t.Errorf("event pid = %d, want 0 in cgroup mode", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}
}

func TestTargetString(t *testing.T) {
	if got := TargetPID(7).String(); got != "pid 7" {
		t.Errorf("String = %q", got)
	}
	if got := TargetCgroup("/a/b", 99).String(); got != "cgroup /a/b (id 99)" {
		t.Errorf("String = %q", got)
	}
	if TargetPID(7).IsCgroup() {
		t.Error("pid target reports cgroup mode")
	}
	if !TargetCgroup("/a", 1).IsCgroup() {
		t.Error("cgroup target does not report cgroup mode")
	}
}
