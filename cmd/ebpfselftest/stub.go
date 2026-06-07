//go:build !linux || !ebpf

// Stub so `go build ./...` / `go vet ./...` succeed in the default lane —
// the real self-test only exists in the Linux eBPF build.
package main

import "fmt"

func main() {
	fmt.Println("ebpf-selftest requires a Linux build with -tags=ebpf")
}
