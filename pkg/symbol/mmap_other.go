//go:build !linux && !darwin

package symbol

import (
	"errors"
	"os"
)

// Off the two platforms ptop runs on, a Module is parsed into heap copies and
// not shared, which is how every Module was built before #137.

func identify(*os.File) (fileKey, bool) { return fileKey{}, false }

func mapFile(*os.File, int64) ([]byte, error) {
	return nil, errors.New("mapping not supported on this platform")
}

func unmapFile([]byte) {}
