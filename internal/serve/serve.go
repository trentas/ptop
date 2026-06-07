// Package serve implements ptop's headless streaming mode (ptop --serve): it
// builds the same collector.Set the TUI uses, fans every collector's output
// into one stream, and serves it over gRPC to any number of unprivileged
// subscribers. ptop holds the elevated capabilities; consumers connect with
// none (see issue #51).
package serve

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// Run starts the gRPC server bound to addr, streaming events for the given
// target pid from cols. It blocks until ctx is cancelled, then stops the server
// and returns. The caller owns the collectors' lifecycle (typically
// set.Collectors() here and set.Stop() after Run returns). addr is
// "unix:///path" or "tcp://host:port".
func Run(ctx context.Context, addr string, pid int, cols []collector.Collector) error {
	lis, cleanup, err := listen(addr)
	if err != nil {
		return err
	}
	defer cleanup()

	hub := NewHub(pid)
	hub.Start(ctx, cols)

	srv := grpc.NewServer()
	pb.RegisterEventStreamServiceServer(srv, &eventStreamService{hub: hub})

	// On cancel, Stop() (not GracefulStop): Subscribe streams are long-lived and
	// only end when the client disconnects, so GracefulStop would block forever.
	// Stop cancels in-flight streams and makes Serve return.
	go func() {
		<-ctx.Done()
		srv.Stop()
	}()

	fmt.Fprintf(os.Stderr, "[ptop] serving events for pid %d on %s\n", pid, addr)
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
