//go:build linux && ebpf && !amd64 && !arm64

package bpf

// No eBPF objects are prebuilt for this architecture (#123). The release ships
// linux/amd64 and linux/arm64; anything else has to run `make gen` for its own
// GOARCH and add the pair of embeds. The vars stay nil rather than holding an
// object built for another architecture, because a wrong-architecture object
// is worse than a missing one: it loads and then lies. Every loader turns a nil
// object into a Start error, which is what the caller already handles.

var cpuBPFObj []byte
var futexBPFObj []byte
var goallocBPFObj []byte
var heapBPFObj []byte
var ioBPFObj []byte
var memoryBPFObj []byte
var networkBPFObj []byte
var procBPFObj []byte
var securityBPFObj []byte
var signalBPFObj []byte
var syscallsBPFObj []byte
var threadsBPFObj []byte
var tlsBPFObj []byte
