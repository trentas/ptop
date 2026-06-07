package serve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

func TestServeUnixEndToEnd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ptop.sock")
	addr := "unix://" + sock

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Fake collector emitting CPU samples until the server shuts down.
	f := newFake(8)
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				select {
				case f.ch <- collector.CpuSample{UsagePct: 33, Timestamp: time.Now()}:
				default:
				}
			}
		}
	}()

	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, addr, 99, []collector.Collector{f}) }()

	// Wait for the listener socket to appear before dialing.
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })

	// Socket must be owner-only (0600).
	if fi, err := os.Stat(sock); err != nil {
		t.Fatalf("stat socket: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket perm = %o, want 600", perm)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewEventStreamServiceClient(conn)
	recvCtx, recvCancel := context.WithTimeout(ctx, 3*time.Second)
	defer recvCancel()
	stream, err := client.Subscribe(recvCtx, &pb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	ev := resp.GetEvent()
	if ev == nil || ev.GetCategory() != pb.Category_CATEGORY_CPU {
		t.Fatalf("unexpected first response: %v", resp)
	}
	if ev.GetPid() != 99 {
		t.Errorf("pid = %d, want 99", ev.GetPid())
	}

	// Shut down and confirm Run returns cleanly and the socket is removed.
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket not removed after shutdown: stat err = %v", err)
	}
}

func TestListenRefusesAllInterfaces(t *testing.T) {
	for _, addr := range []string{"tcp://0.0.0.0:50051", "tcp://:50051", "tcp://[::]:50051"} {
		if _, _, err := listen(addr); err == nil {
			t.Errorf("listen(%q) = nil error, want refusal", addr)
		}
	}
}

func TestListenRejectsUnknownScheme(t *testing.T) {
	if _, _, err := listen("http://localhost:8080"); err == nil {
		t.Errorf("expected error for unsupported scheme")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}
