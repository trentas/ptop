package serve

import (
	"bufio"
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
	sock := shortSock(t)
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
	go func() {
		runErr <- Run(ctx, addr, TargetPID(99), collector.StartBus(ctx, []collector.Collector{f}), nil, Options{})
	}()

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

	// The first response is the target handshake (#94), before any event.
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv handshake: %v", err)
	}
	ti := first.GetMeta().GetTarget()
	if ti == nil {
		t.Fatalf("first response is not a target handshake: %v", first)
	}
	if ti.GetMode() != pb.TargetMode_TARGET_MODE_PID || ti.GetPid() != 99 {
		t.Errorf("handshake = %v, want pid mode for pid 99", ti)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	ev := resp.GetEvent()
	if ev == nil || ev.GetCategory() != pb.Category_CATEGORY_CPU {
		t.Fatalf("unexpected first event: %v", resp)
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

// A slow consumer that falls behind must receive a StreamMeta reporting drops,
// exercised through the real gRPC stream (not just the hub). We never call Recv
// during a large burst, so the transport stalls, the subscriber's bounded
// buffer overflows, and the service surfaces the drop count.
//
// The stall has to be forced, not hoped for: with gRPC's dynamic flow-control
// window the client's stack can absorb the whole burst without the test ever
// reading, the sink queue then never fills, and the test fails having proved
// nothing (it flaked roughly 1 run in 4 that way). Pinning small window sizes
// disables the BDP tuner, so the server blocks in Send while the queue is still
// bounded — which is the condition under test.
// minWindowSize is gRPC's floor for a flow-control window (64KB); anything
// smaller is raised to it. Setting it explicitly is what turns the dynamic
// window off.
const minWindowSize = 64 * 1024

func TestServeBackpressureMetaOverGRPC(t *testing.T) {
	sock := shortSock(t)
	addr := "unix://" + sock

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFake(8192) // holds the burst without blocking the producer
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, addr, TargetPID(1), collector.StartBus(ctx, []collector.Collector{f}), nil, Options{})
	}()
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithInitialWindowSize(minWindowSize),
		grpc.WithInitialConnWindowSize(minWindowSize),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	recvCtx, recvCancel := context.WithTimeout(ctx, 5*time.Second)
	defer recvCancel()
	stream, err := pb.NewEventStreamServiceClient(conn).Subscribe(recvCtx, &pb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Burst far more than subBuffer (256) while the client is not reading.
	for i := 0; i < 5000; i++ {
		f.ch <- collector.CpuSample{UsagePct: float64(i), Timestamp: time.Now()}
	}

	// Now read; a StreamMeta with dropped > 0 must appear.
	var sawMeta bool
	for i := 0; i < 6000; i++ {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		if m := resp.GetMeta(); m != nil && m.GetDropped() > 0 {
			sawMeta = true
			break
		}
	}
	if !sawMeta {
		t.Fatal("expected a StreamMeta with dropped>0 under backpressure")
	}

	cancel()
	<-runErr
}

// Run with Options{JSONLPath} writes an event-level JSONL alongside gRPC.
func TestServeJSONLExport(t *testing.T) {
	sock := shortSock(t)
	jsonl := filepath.Join(t.TempDir(), "events.jsonl")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFake(64)
	go func() {
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				select {
				case f.ch <- collector.CpuSample{UsagePct: 1, Timestamp: time.Now()}:
				default:
				}
			}
		}
	}()

	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, "unix://"+sock, TargetPID(5), collector.StartBus(ctx, []collector.Collector{f}), nil, Options{JSONLPath: jsonl})
	}()
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })

	time.Sleep(200 * time.Millisecond) // let some events flow to the sink
	cancel()
	if err := <-runErr; err != nil { // Run returns → jsonlSink flushed + closed
		t.Fatalf("Run: %v", err)
	}

	f2, err := os.Open(jsonl)
	if err != nil {
		t.Fatalf("open jsonl: %v", err)
	}
	defer f2.Close()
	sc := bufio.NewScanner(f2)

	// Every line is a SubscribeResponse, the same message a gRPC subscriber
	// receives — starting with the target handshake, so the file says what it
	// observed.
	if !sc.Scan() {
		t.Fatal("empty export: no target header")
	}
	if ti := unmarshalResponse(t, sc.Bytes()).GetMeta().GetTarget(); ti.GetPid() != 5 {
		t.Errorf("header target = %v, want pid 5", ti)
	}

	var lines int
	for sc.Scan() {
		if unmarshalResponse(t, sc.Bytes()).GetEvent() == nil {
			continue // a drop notice is legitimate here
		}
		lines++
	}
	if lines == 0 {
		t.Fatal("expected at least one event line in the JSONL export")
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

// shortSock returns a unix socket path short enough for the OS limit. macOS
// caps a socket path (sun_path) at ~104 bytes, and t.TempDir() embeds the test
// name, so long-named tests can blow past it — use a minimal temp dir instead.
func shortSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ptop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
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
