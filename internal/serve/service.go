package serve

import (
	"sync/atomic"

	pb "github.com/trentas/ptop/pkg/streampb"
)

// eventStreamService implements the generated EventStreamServer over a Hub.
type eventStreamService struct {
	pb.UnimplementedEventStreamServer
	hub *Hub
}

// Subscribe registers the client with the hub and streams its queued responses
// until the client disconnects. Whenever the subscriber's drop counter has
// advanced (backpressure), a StreamMeta is sent ahead of the next event so the
// consumer learns it missed some.
func (svc *eventStreamService) Subscribe(req *pb.SubscribeRequest, stream pb.EventStream_SubscribeServer) error {
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
