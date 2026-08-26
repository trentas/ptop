package serve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/trentas/ptop/pkg/collector"
)

// defaultMaxTargets bounds how many processes one on-demand server observes at
// once. Each target loads its own eBPF programs and perf events, so this is a
// resource ceiling, not a policy preference — Options.MaxTargets overrides it.
const defaultMaxTargets = 8

// FeedFactory starts the collectors for one pid and returns the running feed
// plus the stack resolver built over it. The caller of RunOnDemand supplies it:
// WHAT to collect (eBPF or /proc, TLS capture, …) is CLI policy, not the
// server's business. The feed must be stopped by whoever owns it — the registry
// does that when the target's last subscriber leaves.
type FeedFactory func(ctx context.Context, pid int) (*collector.Feed, StackResolver, error)

// A server serves either ONE target fixed at startup or targets its subscribers
// name (#72). Both go through a registry: the service asks for the hub of the
// pid in the request and hands back a release when the stream ends. What
// differs between the two modes is only whether the target was already running.
type registry interface {
	// acquire returns the hub and stack resolver for pid, plus the release to
	// call when done with them. On an on-demand server this starts the target's
	// collectors if it is the first caller. Errors are already gRPC statuses.
	acquire(pid int) (*Hub, StackResolver, func(), error)

	// lookup returns a RUNNING target's resolver without starting anything, so
	// an out-of-band ResolveStack never spins up eBPF for a process nobody is
	// streaming (its stack ids died with the tracer anyway). ok is false when
	// the pid is not being observed or is not this server's target.
	lookup(pid int) (StackResolver, func(), bool)

	// describe is what the startup log and errors call this server's scope.
	describe() string
}

// ─── fixed target ────────────────────────────────────────────────────────────

// fixedRegistry serves the single target given on the command line. It starts
// nothing and releases nothing: the collectors outlive every subscriber.
type fixedRegistry struct {
	target   Target
	hub      *Hub
	resolver StackResolver
}

func noopRelease() {}

func (r *fixedRegistry) check(pid int) error {
	// 0 means "whatever this server observes" — the pre-#72 request shape, and
	// the only accepted value in cgroup mode.
	if pid == 0 || pid == r.target.PID {
		return nil
	}
	return status.Errorf(codes.InvalidArgument,
		"this server observes %s and cannot serve pid %d", r.target, pid)
}

func (r *fixedRegistry) acquire(pid int) (*Hub, StackResolver, func(), error) {
	if err := r.check(pid); err != nil {
		return nil, nil, nil, err
	}
	return r.hub, r.resolver, noopRelease, nil
}

func (r *fixedRegistry) lookup(pid int) (StackResolver, func(), bool) {
	if err := r.check(pid); err != nil {
		return nil, nil, false
	}
	return r.resolver, noopRelease, true
}

func (r *fixedRegistry) describe() string { return r.target.String() }

// ─── targets on demand ───────────────────────────────────────────────────────

// liveTarget is one observed process: its collectors, the hub fanning them out
// and how many subscribers are holding it open.
type liveTarget struct {
	hub      *Hub
	resolver StackResolver
	feed     *collector.Feed
	cancel   context.CancelFunc
	refs     int
}

// onDemandRegistry starts a target's collectors for its first subscriber and
// stops them when the last one disconnects (#72).
//
// One mutex covers the whole map, and it is held across collector startup and
// teardown. That serializes a subscribe for pid B behind one for pid A (an eBPF
// load is on the order of a hundred milliseconds), which is the price of the
// property that matters here: a teardown can never interleave with a subscribe
// for the same pid, so nobody is ever handed a hub whose collectors are being
// stopped underneath them.
type onDemandRegistry struct {
	ctx     context.Context // server lifetime; each target's ctx derives from it
	factory FeedFactory
	max     int

	mu      sync.Mutex
	targets map[int]*liveTarget
}

func newOnDemandRegistry(ctx context.Context, factory FeedFactory, max int) *onDemandRegistry {
	if max <= 0 {
		max = defaultMaxTargets
	}
	return &onDemandRegistry{
		ctx:     ctx,
		factory: factory,
		max:     max,
		targets: make(map[int]*liveTarget),
	}
}

func (r *onDemandRegistry) acquire(pid int) (*Hub, StackResolver, func(), error) {
	if pid <= 0 {
		return nil, nil, nil, status.Error(codes.InvalidArgument,
			"this server has no fixed target: name the pid to observe in SubscribeRequest.pid")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if t := r.targets[pid]; t != nil {
		t.refs++
		return t.hub, t.resolver, r.releaseFunc(pid), nil
	}
	if len(r.targets) >= r.max {
		return nil, nil, nil, status.Errorf(codes.ResourceExhausted,
			"already observing %d processes (limit %d): disconnect a subscriber or raise --serve-max-targets",
			len(r.targets), r.max)
	}
	// Check before loading anything: a typo'd pid should fail as a clear
	// NotFound, not as a set of collectors that quietly observe nothing.
	if err := processExists(pid); err != nil {
		return nil, nil, nil, status.Errorf(codes.NotFound, "%v", err)
	}

	ctx, cancel := context.WithCancel(r.ctx)
	feed, resolver, err := r.factory(ctx, pid)
	if err != nil {
		cancel()
		return nil, nil, nil, status.Errorf(codes.Internal, "start collectors for pid %d: %v", pid, err)
	}

	buildID := ""
	if resolver != nil {
		buildID = resolver.ProcessBuildID()
	}
	hub := NewHub(TargetPID(pid), buildID, feed.Set)
	hub.Start(ctx, feed.Bus)

	t := &liveTarget{hub: hub, resolver: resolver, feed: feed, cancel: cancel, refs: 1}
	r.targets[pid] = t
	fmt.Fprintf(os.Stderr, "[ptop] observing pid %d (%d target(s) live)\n", pid, len(r.targets))
	hub.reportProbes()
	return hub, resolver, r.releaseFunc(pid), nil
}

func (r *onDemandRegistry) lookup(pid int) (StackResolver, func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.targets[pid]
	if t == nil {
		return nil, nil, false
	}
	t.refs++
	return t.resolver, r.releaseFunc(pid), true
}

// releaseFunc returns a release that runs at most once, so a double defer
// cannot drop a reference twice and tear a target down under its subscribers.
func (r *onDemandRegistry) releaseFunc(pid int) func() {
	var once sync.Once
	return func() { once.Do(func() { r.release(pid) }) }
}

func (r *onDemandRegistry) release(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.targets[pid]
	if t == nil {
		return
	}
	t.refs--
	if t.refs > 0 {
		return
	}
	delete(r.targets, pid)
	t.cancel()    // detaches the hub and ends the bus drain goroutines
	t.feed.Stop() // releases the eBPF tracers — nothing lingers for a pid nobody watches
	fmt.Fprintf(os.Stderr, "[ptop] released pid %d (%d target(s) live)\n", pid, len(r.targets))
}

func (r *onDemandRegistry) describe() string {
	return fmt.Sprintf("targets chosen by subscribers (max %d)", r.max)
}

// liveCount is how many targets are running. Tests assert teardown with it.
func (r *onDemandRegistry) liveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.targets)
}

// processExists reports whether the pid can be observed at all. kill(pid, 0)
// delivers no signal, it only performs the existence/permission check — the
// same probe the TUI path uses before starting. EPERM means it exists but
// belongs to another user: the collectors degrade rather than fail, so it is
// allowed through here.
func processExists(pid int) error {
	err := syscall.Kill(pid, 0)
	switch {
	case err == nil, errors.Is(err, syscall.EPERM):
		return nil
	case errors.Is(err, syscall.ESRCH):
		return fmt.Errorf("process %d does not exist", pid)
	default:
		return fmt.Errorf("cannot check process %d: %w", pid, err)
	}
}
