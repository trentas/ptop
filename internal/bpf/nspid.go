package bpf

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
)

// NSpidChain reads the NSpid line of a /proc status file (/proc/<pid>/status
// or /proc/<pid>/task/<tid>/status): the task's id in every pid namespace,
// from the one this /proc belongs to (first) down to the task's own (last).
// One entry means the task lives in the namespace ptop reads /proc from.
//
// nil when the file cannot be read or has no NSpid line (kernels before 4.1).
// A caller that needs the innermost id must not guess it then: the number /proc
// shows is the right one only when the chain has one entry (#197).
func NSpidChain(statusPath string) []int {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil
	}
	return parseNSpid(data)
}

// parseNSpid extracts the NSpid chain from the contents of a status file.
func parseNSpid(data []byte) []int {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "NSpid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		chain := make([]int, 0, len(fields))
		for _, f := range fields {
			v, err := strconv.Atoi(f)
			if err != nil || v <= 0 {
				return nil
			}
			chain = append(chain, v)
		}
		if len(chain) == 0 {
			return nil
		}
		return chain
	}
	return nil
}
