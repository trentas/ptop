package serve

import (
	"context"
	"os"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/trentas/ptop/pkg/collector"
)

// testFactory hands out a feed over a fake collector per pid, records how many
// times it was asked to start one, and keeps each target's context so a test
// can prove the teardown actually cancelled it.
type testFactory struct {
	mu    sync.Mutex
	calls map[int]int
	ctxs  map[int]context.Context
	feeds map[int]*fakeCollector
	err   error
}

func newTestFactory() *testFactory {
	return &testFactory{
		calls: map[int]int{},
		ctxs:  map[int]context.Context{},
		feeds: map[int]*fakeCollector{},
	}
}

func (f *testFactory) make(ctx context.Context, pid int) (*collector.Feed, StackResolver, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, nil, f.err
	}
	f.calls[pid]++
	f.ctxs[pid] = ctx
	c := newFake(8)
	f.feeds[pid] = c
	feed := &collector.Feed{
		Set: collector.NewSet(collector.SetConfig{}),
		Bus: collector.StartBus(ctx, []collector.Collector{c}),
	}
	return feed, nil, nil
}

func (f *testFactory) callsFor(pid int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[pid]
}

func (f *testFactory) ctxFor(pid int) context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ctxs[pid]
}

func statusCode(t *testing.T, err error) codes.Code {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	return st.Code()
}

// Collectors start once for a target however many subscribers it has, and are
// released only when the last one lets go.
func TestOnDemandRefcount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newTestFactory()
	reg := newOnDemandRegistry(ctx, f.make, 4)
	pid := os.Getpid()

	hub1, _, release1, err := reg.acquire(pid)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	hub2, _, release2, err := reg.acquire(pid)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if hub1 != hub2 {
		t.Error("two subscribers of one pid got different hubs — they'd be reading different collectors")
	}
	if n := f.callsFor(pid); n != 1 {
		t.Errorf("factory called %d times for one target, want 1", n)
	}

	release1()
	if reg.liveCount() != 1 {
		t.Fatal("target torn down while a subscriber still holds it")
	}
	release1() // idempotent: a double release must not drop someone else's ref
	if reg.liveCount() != 1 {
		t.Fatal("a repeated release dropped a live reference")
	}

	targetCtx := f.ctxFor(pid)
	release2()
	if reg.liveCount() != 0 {
		t.Error("target still live after its last subscriber left")
	}
	if targetCtx.Err() == nil {
		t.Error("target context not cancelled on teardown — the hub is still attached to the bus")
	}

	// A later subscriber gets a fresh target, not the corpse of the old one.
	if _, _, release, err := reg.acquire(pid); err != nil {
		t.Fatalf("re-acquire: %v", err)
	} else {
		defer release()
	}
	if n := f.callsFor(pid); n != 2 {
		t.Errorf("factory called %d times after teardown+re-acquire, want 2", n)
	}
}

func TestOnDemandRejections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newTestFactory()
	reg := newOnDemandRegistry(ctx, f.make, 1) // cap of one target

	// No pid at all: this server has no target of its own to fall back on.
	if _, _, _, err := reg.acquire(0); statusCode(t, err) != codes.InvalidArgument {
		t.Errorf("acquire(0) = %v, want InvalidArgument", err)
	}

	// A pid that does not exist fails before any collector is loaded.
	const gonePID = 0x7FFFFFF0
	if _, _, _, err := reg.acquire(gonePID); statusCode(t, err) != codes.NotFound {
		t.Errorf("acquire(nonexistent) = %v, want NotFound", err)
	}
	if f.callsFor(gonePID) != 0 {
		t.Error("collectors were started for a pid that does not exist")
	}

	// The cap is enforced, and says how to raise it.
	_, _, release, err := reg.acquire(os.Getpid())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	_, _, _, err = reg.acquire(os.Getppid())
	if statusCode(t, err) != codes.ResourceExhausted {
		t.Fatalf("acquire beyond the cap = %v, want ResourceExhausted", err)
	}
	if got := status.Convert(err).Message(); got == "" {
		t.Error("cap error has no message")
	}
	if reg.liveCount() != 1 {
		t.Errorf("liveCount = %d after a refused acquire, want 1", reg.liveCount())
	}
}

// A factory that fails must not leave a half-registered target behind.
func TestOnDemandFactoryFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newTestFactory()
	f.err = context.DeadlineExceeded
	reg := newOnDemandRegistry(ctx, f.make, 4)

	if _, _, _, err := reg.acquire(os.Getpid()); statusCode(t, err) != codes.Internal {
		t.Errorf("acquire with a failing factory = %v, want Internal", err)
	}
	if reg.liveCount() != 0 {
		t.Errorf("liveCount = %d after a failed start, want 0", reg.liveCount())
	}
}

// ResolveStack must never start collectors: an id from a target nobody is
// streaming refers to a stack map that is already gone.
func TestOnDemandLookupNeverStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newTestFactory()
	reg := newOnDemandRegistry(ctx, f.make, 4)
	pid := os.Getpid()

	if _, _, ok := reg.lookup(pid); ok {
		t.Error("lookup found a target nobody is observing")
	}
	if f.callsFor(pid) != 0 {
		t.Error("lookup started collectors")
	}

	_, _, release, err := reg.acquire(pid)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, releaseLookup, ok := reg.lookup(pid); !ok {
		t.Error("lookup missed a running target")
	} else {
		releaseLookup()
	}
	release()
	if reg.liveCount() != 0 {
		t.Error("a lookup's reference outlived its release")
	}
}

// The fixed-target server answers for its own pid (or 0, the pre-#72 request
// shape) and refuses to pretend it can serve another process.
func TestFixedRegistryChecksPID(t *testing.T) {
	reg := &fixedRegistry{target: TargetPID(42), hub: NewHub(TargetPID(42), "")}

	for _, pid := range []int{0, 42} {
		if _, _, _, err := reg.acquire(pid); err != nil {
			t.Errorf("acquire(%d) = %v, want accepted", pid, err)
		}
	}
	_, _, _, err := reg.acquire(7)
	if statusCode(t, err) != codes.InvalidArgument {
		t.Errorf("acquire(7) = %v, want InvalidArgument", err)
	}
	if _, _, ok := reg.lookup(7); ok {
		t.Error("lookup(7) succeeded on a server observing pid 42")
	}

	// Cgroup mode has no pid to name, so only 0 is meaningful.
	cg := &fixedRegistry{target: TargetCgroup("/x.scope", 99), hub: NewHub(TargetCgroup("/x.scope", 99), "")}
	if _, _, _, err := cg.acquire(0); err != nil {
		t.Errorf("cgroup acquire(0) = %v, want accepted", err)
	}
	if _, _, _, err := cg.acquire(42); statusCode(t, err) != codes.InvalidArgument {
		t.Errorf("cgroup acquire(42) = %v, want InvalidArgument", err)
	}
}
