package serve

import (
	"testing"

	"github.com/trentas/ptop/pkg/symbol"
)

// tagResolver answers with a frame naming itself, so a test can tell which
// source a dispatched id actually reached.
type tagResolver struct {
	tag     string
	buildID string
	seen    uint64 // last id it was asked for (after the tag was stripped)
}

func (r *tagResolver) ProcessBuildID() string { return r.buildID }

func (r *tagResolver) ResolveStack(id uint64) ([]symbol.Frame, bool) {
	r.seen = id
	return []symbol.Frame{{Func: r.tag}}, true
}

// An id emitted before #89 (heap, source 0) must keep its exact wire value.
func TestTaggedStackIDHeapUnchanged(t *testing.T) {
	if got := taggedStackID(StackSourceHeap, 42); got != 42 {
		t.Errorf("heap id = %d, want 42 (source 0 is the identity tag)", got)
	}
	if got := taggedStackID(StackSourceFutex, 42); got != 1<<32|42 {
		t.Errorf("futex id = %#x, want %#x", got, uint64(1)<<32|42)
	}
	for _, src := range []StackSource{StackSourceHeap, StackSourceFutex} {
		if got := taggedStackID(src, -1); got != 0 {
			t.Errorf("source %d: failed walk = %d, want 0", src, got)
		}
	}
}

// Two tracers, two independent id spaces: the same kernel id must reach the
// tracer that captured it, never the other one.
func TestCombinedResolverRoutesBySource(t *testing.T) {
	heap := &tagResolver{tag: "heap"}
	futex := &tagResolver{tag: "futex", buildID: "bid"}
	r := CombineStackResolvers(map[StackSource]StackResolver{
		StackSourceHeap:  heap,
		StackSourceFutex: futex,
	})

	frames, ok := r.ResolveStack(taggedStackID(StackSourceFutex, 7))
	if !ok || len(frames) != 1 || frames[0].Func != "futex" {
		t.Fatalf("futex id resolved to %v (ok=%v), want the futex tracer", frames, ok)
	}
	if futex.seen != 7 {
		t.Errorf("futex tracer got id %d, want the bare kernel id 7", futex.seen)
	}

	frames, ok = r.ResolveStack(taggedStackID(StackSourceHeap, 7))
	if !ok || frames[0].Func != "heap" {
		t.Fatalf("heap id resolved to %v (ok=%v), want the heap tracer", frames, ok)
	}
}

func TestCombinedResolverUnknownIDs(t *testing.T) {
	r := CombineStackResolvers(map[StackSource]StackResolver{
		StackSourceHeap: &tagResolver{tag: "heap"},
	})
	if _, ok := r.ResolveStack(0); ok {
		t.Error("id 0 resolved; it is reserved for 'no stack captured'")
	}
	// A futex id with no futex collector running (Go target, no libc): not
	// found, never silently answered by the heap tracer.
	if _, ok := r.ResolveStack(taggedStackID(StackSourceFutex, 3)); ok {
		t.Error("id of an absent source resolved; want not-found")
	}
}

// The build-id is the target executable's, so any source can supply it — but
// only a source that has one.
func TestCombinedResolverBuildID(t *testing.T) {
	r := CombineStackResolvers(map[StackSource]StackResolver{
		StackSourceHeap:  &tagResolver{tag: "heap"}, // cgroup mode: no build-id
		StackSourceFutex: &tagResolver{tag: "futex", buildID: "bid"},
	})
	if got := r.ProcessBuildID(); got != "bid" {
		t.Errorf("ProcessBuildID = %q, want %q", got, "bid")
	}
}

// With nothing capturing stacks, Run must receive a genuinely nil resolver —
// not a wrapper that reports found=false forever.
func TestCombineStackResolversEmpty(t *testing.T) {
	if r := CombineStackResolvers(nil); r != nil {
		t.Errorf("CombineStackResolvers(nil) = %v, want nil", r)
	}
	if r := CombineStackResolvers(map[StackSource]StackResolver{}); r != nil {
		t.Errorf("CombineStackResolvers(empty) = %v, want nil", r)
	}
}
