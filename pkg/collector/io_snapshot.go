package collector

// IOEBPFSnapshot is what the eBPF io collector publishes every window. The
// model updates IOStats.TopFiles and IOStats.LatencyBuckets from it.
//
// TopFiles are cumulative since the probe attached. Buckets count the calls
// that finished in the window since the previous snapshot, so a consumer sums
// them to get a total. A row named IOLostPath carries the calls the kernel had
// no room to attribute to a file (#181).
type IOEBPFSnapshot struct {
	TopFiles []IOFileStats
	Buckets  []LatencyBucket
}

// IOLostPath names the TopFiles row of the calls the io probe counted but could
// attribute to no file: its per-file map was full (#181). It is absent while
// there are none.
const IOLostPath = "(no file: io map full)"
