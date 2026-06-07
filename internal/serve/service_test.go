package serve

import (
	"context"
	"testing"

	pb "github.com/trentas/ptop/pkg/streampb"
	"github.com/trentas/ptop/pkg/symbol"
)

// fakeResolver is a StackResolver driven by the test.
type fakeResolver struct {
	buildID string
	frames  map[uint64][]symbol.Frame
}

func (r *fakeResolver) ProcessBuildID() string { return r.buildID }
func (r *fakeResolver) ResolveStack(id uint64) ([]symbol.Frame, bool) {
	fr, ok := r.frames[id]
	return fr, ok
}

func TestResolveStackRPC(t *testing.T) {
	res := &fakeResolver{
		buildID: "bid",
		frames: map[uint64][]symbol.Frame{
			42: {
				{Func: "main.leak", File: "/build/main.go", Line: 7, Module: "app", Offset: 0x1a3, BuildID: "bid"},
				{Func: "main.main", File: "/build/main.go", Line: 20, Module: "app", Offset: 0x2b4},
			},
		},
	}
	svc := &eventStreamService{resolver: res}

	// Known id → found, frames mapped leaf-first 1:1.
	resp, err := svc.ResolveStack(context.Background(), &pb.ResolveStackRequest{StackId: 42})
	if err != nil {
		t.Fatalf("ResolveStack: %v", err)
	}
	if !resp.GetFound() {
		t.Fatal("found = false, want true for a known id")
	}
	if n := len(resp.GetFrames()); n != 2 {
		t.Fatalf("frames = %d, want 2", n)
	}
	f0 := resp.GetFrames()[0]
	if f0.GetFunc() != "main.leak" || f0.GetFile() != "/build/main.go" || f0.GetLine() != 7 ||
		f0.GetModule() != "app" || f0.GetOffset() != 0x1a3 || f0.GetBuildId() != "bid" {
		t.Errorf("frame[0] = %+v", f0)
	}

	// Unknown id → found=false, no error.
	resp, err = svc.ResolveStack(context.Background(), &pb.ResolveStackRequest{StackId: 99})
	if err != nil {
		t.Fatalf("ResolveStack(unknown): %v", err)
	}
	if resp.GetFound() || len(resp.GetFrames()) != 0 {
		t.Errorf("unknown id: found=%v frames=%d, want false/0", resp.GetFound(), len(resp.GetFrames()))
	}
}

func TestResolveStackRPCNilResolver(t *testing.T) {
	// A build without symbolization (nil resolver) never errors — just not-found.
	svc := &eventStreamService{}
	resp, err := svc.ResolveStack(context.Background(), &pb.ResolveStackRequest{StackId: 1})
	if err != nil {
		t.Fatalf("ResolveStack: %v", err)
	}
	if resp.GetFound() {
		t.Error("found = true with no resolver, want false")
	}
}
