// Package serve implements ptop's headless streaming mode (ptop --serve): it
// builds the same collector.Set the TUI uses, fans every collector's output
// into one stream, and serves it over gRPC to any number of unprivileged
// subscribers. ptop holds the elevated capabilities; consumers connect with
// none (see issue #51).
package serve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// Target describes what a server observes. It is reported to every subscriber
// as the stream handshake (TargetInfo, #94), because the two modes aggregate
// differently: in PID mode every event belongs to one process, while in cgroup
// mode events come from anywhere in the subtree.
type Target struct {
	// PID mode: the target pid. 0 in cgroup mode.
	PID int

	// Cgroup mode: the resolved absolute cgroup path and its id (the directory
	// inode). Empty/0 in pid mode.
	CgroupPath string
	CgroupID   uint64
}

// TargetPID names a single process.
func TargetPID(pid int) Target { return Target{PID: pid} }

// TargetCgroup names a cgroup subtree, already resolved to a path and id.
func TargetCgroup(path string, id uint64) Target {
	return Target{CgroupPath: path, CgroupID: id}
}

// IsCgroup reports whether t names a cgroup subtree rather than a pid.
func (t Target) IsCgroup() bool { return t.CgroupPath != "" }

func (t Target) String() string {
	if t.IsCgroup() {
		return fmt.Sprintf("cgroup %s (id %d)", t.CgroupPath, t.CgroupID)
	}
	return fmt.Sprintf("pid %d", t.PID)
}

// Options tunes a Run beyond the address/target. The zero value is the plain
// gRPC-only server.
type Options struct {
	// JSONLPath, if set, also writes every event as one protojson line to this
	// file (an interchangeable sink alongside the gRPC subscribers).
	JSONLPath string

	// TLS carries the transport security of a tcp:// endpoint (issue #95).
	// Serving tcp:// in cleartext requires TLS.AllowInsecure; a unix socket
	// takes no TLS at all. See serverCredentials for the full policy.
	TLS TLSOptions

	// MaxTargets caps how many processes a RunOnDemand server observes at once
	// (#72); 0 uses defaultMaxTargets. Each target carries its own eBPF programs
	// and perf events, so this is a resource ceiling. Ignored with a fixed
	// target — there is only ever one.
	MaxTargets int

	// Ready, if set, is closed once the endpoint is bound and the server is
	// about to serve. It exists so a caller that runs Run in a goroutine can
	// tell "up" from "failed at startup" without racing a timer — everything
	// that can go wrong (address, TLS material, bind) happens before it closes.
	// Run closes it exactly once, and never closes it on a startup failure.
	Ready chan<- struct{}
}

// Run starts the gRPC server bound to addr, streaming events for the given
// target — a pid or a cgroup subtree — off bus, the shared fan-out over the
// running collectors (#71). It blocks until ctx is cancelled, then stops the
// server and returns. The caller owns the feed's lifecycle (typically
// collector.StartFeed here and feed.Stop() after Run returns), and may attach
// other consumers to the same bus — the TUI does, under --serve --tui. addr is
// "unix:///path" or "tcp://host:port"; a tcp:// endpoint must carry TLS
// material or an explicit opt-in to cleartext (see serverCredentials).
//
// resolver (optional, nil-safe) symbolizes captured stacks: it stamps the
// per-process build-id onto every StackRef and backs the ResolveStack RPC.
// Build it with CombineStackResolvers over the collectors that captured stacks
// (heap, futex); nil leaves events without stack references.
func Run(ctx context.Context, addr string, target Target, bus *collector.Bus, resolver StackResolver, opts Options) error {
	// Resolve transport security first: a missing certificate or a refused
	// cleartext endpoint should fail before anything is bound.
	creds, mode, err := serverCredentials(addr, opts.TLS)
	if err != nil {
		return err
	}

	lis, cleanup, err := listen(addr)
	if err != nil {
		return err
	}
	defer cleanup()

	reg := fixedTargetRegistry(ctx, target, bus, resolver)
	return runServer(ctx, lis, creds, mode, reg, reg.hub, opts)
}

// RunOnDemand starts the gRPC server bound to addr with NO target of its own
// (#72): each subscriber names the pid it wants in SubscribeRequest.pid, and
// factory starts that process's collectors for its first subscriber. They are
// released when its last subscriber disconnects, so nothing keeps eBPF loaded
// for a process nobody is watching. opts.MaxTargets caps how many run at once.
//
// Everything else matches Run: the same transport-security policy, the same
// event stream, the same handshake — a subscriber cannot tell how the server
// was started except by what TargetInfo says.
func RunOnDemand(ctx context.Context, addr string, factory FeedFactory, opts Options) error {
	if factory == nil {
		return errors.New("serve: RunOnDemand needs a FeedFactory")
	}
	// An event-level export has one TargetInfo header and one file; with targets
	// coming and going there is no single scope it could honestly claim. Refuse
	// before binding, like every other startup misconfiguration.
	if opts.JSONLPath != "" {
		return errors.New("serve: --export needs a fixed target (--pid), not one chosen per subscriber")
	}

	creds, mode, err := serverCredentials(addr, opts.TLS)
	if err != nil {
		return err
	}

	lis, cleanup, err := listen(addr)
	if err != nil {
		return err
	}
	defer cleanup()

	return runServer(ctx, lis, creds, mode, newOnDemandRegistry(ctx, factory, opts.MaxTargets), nil, opts)
}

// fixedTargetRegistry starts the hub for a server whose target was named on the
// command line, and wraps it in the registry the service talks to.
func fixedTargetRegistry(ctx context.Context, target Target, bus *collector.Bus, resolver StackResolver) *fixedRegistry {
	buildID := ""
	if resolver != nil {
		buildID = resolver.ProcessBuildID()
	}
	hub := NewHub(target, buildID)
	hub.Start(ctx, bus)
	return &fixedRegistry{target: target, hub: hub, resolver: resolver}
}

// runServer owns everything after the listener exists: the sinks, the gRPC
// server and the shutdown. Split out of Run so tests can drive a real server on
// an ephemeral tcp port (listen() picks it, only lis knows it).
// reg maps a request's pid to the target serving it; sinkHub is the one hub a
// JSONL export can attach to, and is nil when targets are chosen per subscriber
// (there is no single stream to write).
func runServer(ctx context.Context, lis net.Listener, creds credentials.TransportCredentials, mode string, reg registry, sinkHub *Hub, opts Options) error {
	// Optional JSONL sink: a non-gRPC consumer of the same event stream.
	if opts.JSONLPath != "" && sinkHub != nil {
		js, err := newJSONLSink(opts.JSONLPath, sinkHub.targetInfo())
		if err != nil {
			return fmt.Errorf("serve: jsonl export: %w", err)
		}
		sinkHub.AddSink(js)
		// RemoveSink before Close so no Emit races the channel close.
		defer func() { sinkHub.RemoveSink(js); _ = js.Close() }()
		fmt.Fprintf(os.Stderr, "[ptop] also exporting events to %s\n", opts.JSONLPath)
	}

	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterEventStreamServiceServer(srv, &eventStreamService{reg: reg})

	// On cancel, Stop() (not GracefulStop): Subscribe streams are long-lived and
	// only end when the client disconnects, so GracefulStop would block forever.
	// Stop cancels in-flight streams and makes Serve return.
	go func() {
		<-ctx.Done()
		srv.Stop()
	}()

	if mode == modePlaintext {
		fmt.Fprintln(os.Stderr, "[ptop] ⚠ --serve-insecure: this TCP stream is unencrypted and")
		fmt.Fprintln(os.Stderr, "       unauthenticated. Anyone who reaches the port reads process internals.")
	}
	fmt.Fprintf(os.Stderr, "[ptop] serving events for %s on %s://%s (%s)\n",
		reg.describe(), lis.Addr().Network(), lis.Addr().String(), mode)
	if opts.Ready != nil {
		close(opts.Ready)
	}
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// listen parses addr and returns a listener plus a cleanup func. For unix
// sockets it removes a stale file, restricts the socket to the owner (0600),
// and unlinks it on cleanup. For tcp it refuses binding all interfaces
// implicitly — the socket exposes process internals, so the caller must pick
// loopback or an explicit interface IP.
func listen(addr string) (net.Listener, func(), error) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		path := strings.TrimPrefix(addr, "unix://")
		if path == "" {
			return nil, nil, fmt.Errorf("serve: empty unix socket path in %q", addr)
		}
		// Remove a stale socket from a previous run (only if it is a socket).
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(path)
		}
		lis, err := net.Listen("unix", path)
		if err != nil {
			return nil, nil, fmt.Errorf("serve: listen unix %q: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			_ = lis.Close()
			return nil, nil, fmt.Errorf("serve: chmod socket %q: %w", path, err)
		}
		return lis, func() { _ = os.Remove(path) }, nil

	case strings.HasPrefix(addr, "tcp://"):
		hostport := strings.TrimPrefix(addr, "tcp://")
		host, _, err := net.SplitHostPort(hostport)
		if err != nil {
			return nil, nil, fmt.Errorf("serve: invalid tcp address %q: %w", addr, err)
		}
		if isAllInterfaces(host) {
			return nil, nil, fmt.Errorf(
				"serve: refusing to bind all interfaces (%q) — the stream exposes process "+
					"internals; bind 127.0.0.1 or a specific interface IP instead", addr)
		}
		lis, err := net.Listen("tcp", hostport)
		if err != nil {
			return nil, nil, fmt.Errorf("serve: listen tcp %q: %w", hostport, err)
		}
		return lis, func() {}, nil

	default:
		return nil, nil, fmt.Errorf("serve: unsupported address %q (use unix:///path or tcp://host:port)", addr)
	}
}

// isAllInterfaces reports whether host means "every interface" — empty, the
// IPv4 unspecified 0.0.0.0, or the IPv6 unspecified ::.
func isAllInterfaces(host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return true
	}
	return false
}
