package serve

import "github.com/trentas/ptop/pkg/symbol"

// Stack ids on the wire are namespaced by their source (#89). Several tracers
// capture stacks, each into its own kernel BPF_MAP_TYPE_STACK_TRACE map, and
// their ids are independent counters — id 7 in the heap map and id 7 in the
// futex map are different stacks. A bare kernel id on the wire would therefore
// be ambiguous, and ResolveStack would happily answer with the wrong stack.
//
// So a wire stack id carries its source in the high 32 bits and the kernel id
// in the low 32:
//
//	stack_id = source<<32 | uint32(kernel_id)
//
// Heap is source 0, which keeps every id emitted before #89 byte-identical.
// 0 is reserved for "no stack" — a walk that failed, or an event with none —
// so it never resolves.
type StackSource uint32

const (
	StackSourceHeap  StackSource = 0 // heap_stacks (#53/#54)
	StackSourceFutex StackSource = 1 // futex_stacks (#89)
)

// taggedStackID widens a kernel stack id for the wire, stamping its source. A
// negative sentinel (the walk failed) becomes 0, which ResolveStack reports as
// not-found — the same as any id the kernel has since evicted.
func taggedStackID(src StackSource, id int32) uint64 {
	if id < 0 {
		return 0
	}
	return uint64(src)<<32 | uint64(uint32(id))
}

// combinedResolver routes a wire stack id back to the tracer that captured it.
type combinedResolver struct {
	order    []StackSource // build-id lookup order; deterministic
	bySource map[StackSource]StackResolver
}

// CombineStackResolvers returns one StackResolver over several capturing
// tracers, dispatching each id to the source encoded in it. Sources with a nil
// resolver are dropped; the result is nil when nothing is left, so a caller can
// pass it straight to Run (a nil resolver disables stack references).
func CombineStackResolvers(bySource map[StackSource]StackResolver) StackResolver {
	c := &combinedResolver{bySource: make(map[StackSource]StackResolver, len(bySource))}
	// Fixed order (not map order) so ProcessBuildID is stable across runs.
	for _, src := range []StackSource{StackSourceHeap, StackSourceFutex} {
		if r := bySource[src]; r != nil {
			c.order = append(c.order, src)
			c.bySource[src] = r
		}
	}
	if len(c.order) == 0 {
		return nil
	}
	return c
}

// ProcessBuildID is the target executable's build-id. Every source symbolizes
// the same target, so the first non-empty answer is the answer.
func (c *combinedResolver) ProcessBuildID() string {
	for _, src := range c.order {
		if id := c.bySource[src].ProcessBuildID(); id != "" {
			return id
		}
	}
	return ""
}

// ResolveStack strips the source tag and asks that tracer for the frames.
func (c *combinedResolver) ResolveStack(stackID uint64) ([]symbol.Frame, bool) {
	if stackID == 0 {
		return nil, false // reserved: no stack was captured
	}
	r := c.bySource[StackSource(stackID>>32)]
	if r == nil {
		return nil, false
	}
	return r.ResolveStack(stackID & 0xFFFFFFFF)
}
