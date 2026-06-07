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

// eventStreamService implements the generated EventStreamServiceServer over a Hub.
type eventStreamService struct {
	pb.UnimplementedEventStreamServiceServer
	hub      *Hub
	resolver StackResolver // nil when the build has no symbolization
}

// ResolveStack symbolizes a stack id seen on the stream into its leaf-first
// frames (out-of-band so high-rate events stay small). Resolution is
// best-effort: an unknown id, or no resolver, yields found=false (not an error).
func (svc *eventStreamService) ResolveStack(_ context.Context, req *pb.ResolveStackRequest) (*pb.ResolveStackResponse, error) {
	if svc.resolver == nil {
		return &pb.ResolveStackResponse{Found: false}, nil
	}
	frames, ok := svc.resolver.ResolveStack(req.GetStackId())
	if !ok {
		return &pb.ResolveStackResponse{Found: false}, nil
	}
	return &pb.ResolveStackResponse{Found: true, Frames: stackFrames(frames)}, nil
}

// Subscribe registers the client with the hub and streams its queued responses
// until the client disconnects. Whenever the subscriber's drop counter has
// advanced (backpressure), a StreamMeta is sent ahead of the next event so the
// consumer learns it missed some.
func (svc *eventStreamService) Subscribe(req *pb.SubscribeRequest, stream pb.EventStreamService_SubscribeServer) error {
	sub := svc.hub.subscribe(req.GetCategories())
	defer svc.hub.unsubscribe(sub)

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
