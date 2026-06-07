// Fixture binary cross-compiled for linux by pkg/symbol's tests to exercise
// gosym-based symbolization. It is not part of the module build (the go tool
// ignores testdata), so its imports stay minimal.
package main

import "fmt"

//go:noinline
func leakyAlloc(n int) []byte {
	return make([]byte, n)
}

func main() {
	var kept [][]byte
	for i := 0; i < 3; i++ {
		kept = append(kept, leakyAlloc(1024))
	}
	fmt.Println(len(kept))
}
