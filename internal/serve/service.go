package serve

import (
	"context"
	"sync/atomic"

	pb "github.com/trentas/ptop/pkg/streampb"
	"github.com/trentas/ptop/pkg/symbol"
)

// StackResolver turns a captured stack id (seen on the stream as
// Event.stack.stack_id or HeapCallSite.stack_id) into its symbolized frames and
// reports the target's build-id (a stable per-process cache key). The eBPF heap
// collector implements it; a nil resolver disables stack references and makes
// ResolveStack report not-found.
type StackResolver interface {
	// ProcessBuildID is the target executable's GNU build-id, or "" if none.
	ProcessBuildID() string
	// ResolveStack returns the leaf-first frames for a stack id; ok is false
	// when the id is unknown or symbolization is unavailable.
	ResolveStack(stackID uint64) (frames []symbol.Frame, ok bool)
}

// eventStreamService implements the generated EventStreamServiceServer. It owns
// no target of its own: the registry maps the pid in a request to the hub and
// resolver serving it, whether that target was fixed at startup or is being
// observed on demand (#72).
type eventStreamService struct {
	pb.UnimplementedEventStreamServiceServer
	reg registry
}

// ResolveStack symbolizes a stack id seen on the stream into its leaf-first
// frames (out-of-band so high-rate events stay small). Resolution is
// best-effort: an unknown id, no resolver, or a pid nobody is observing yields
// found=false (not an error) — a stack id outlives nothing, so there is no
// point starting collectors to answer.
func (svc *eventStreamService) ResolveStack(_ context.Context, req *pb.ResolveStackRequest) (*pb.ResolveStackResponse, error) {
	resolver, release, ok := svc.reg.lookup(int(req.GetPid()))
	if !ok || resolver == nil {
		if ok {
			release()
		}
		return &pb.ResolveStackResponse{Found: false}, nil
	}
	defer release()
	frames, ok := resolver.ResolveStack(req.GetStackId())
	if !ok {
		return &pb.ResolveStackResponse{Found: false}, nil
	}
	return &pb.ResolveStackResponse{Found: true, Frames: stackFrames(frames)}, nil
}

// Subscribe registers the client with the hub, sends the target handshake, and
// streams its queued responses until the client disconnects. Whenever the
// subscriber's drop counter has
// advanced (backpressure), a StreamMeta is sent ahead of the next event so the
// consumer learns it missed some.
func (svc *eventStreamService) Subscribe(req *pb.SubscribeRequest, stream pb.EventStreamService_SubscribeServer) error {
	// Acquiring the target is what starts its collectors on an on-demand
	// server, and the release below is what stops them once the last subscriber
	// is gone (#72).
	hub, _, release, err := svc.reg.acquire(int(req.GetPid()))
	if err != nil {
		return err
	}
	defer release()

	sub := hub.subscribe(req.GetCategories())
	defer hub.unsubscribe(sub)

	// Handshake (#94): the scope of the stream, before anything is streamed. A
	// consumer needs it to read what follows correctly — notably, cgroup-mode
	// events carry no single pid.
	handshake := &pb.SubscribeResponse{
		Kind: &pb.SubscribeResponse_Meta{Meta: &pb.StreamMeta{Target: hub.targetInfo()}},
	}
	if err := stream.Send(handshake); err != nil {
		return err
	}

	ctx := stream.Context()
	var lastDropped uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case resp := <-sub.ch:
			if cur := atomic.LoadUint64(&sub.dropped); cur != lastDropped {
				lastDropped = cur
				meta := &pb.SubscribeResponse{
					Kind: &pb.SubscribeResponse_Meta{Meta: &pb.StreamMeta{Dropped: cur}},
				}
				if err := stream.Send(meta); err != nil {
					return err
				}
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}
