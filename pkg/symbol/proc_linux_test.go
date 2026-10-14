//go:build linux

package symbol

import (
	"os"
	"reflect"
	"testing"
)

// The live-process shape of #137: every collector of a target holds its own
// Symbolizer, and the Go allocation probe opens the executable through
// /proc/<pid>/exe while the symbolizers open it through the path in
// /proc/<pid>/maps. All of them must land on one image — a parse apiece is
// the ~1 GB the report measured.
func TestSymbolizersOfOneProcessShareItsImage(t *testing.T) {
	pc := uint64(reflect.ValueOf(TestSymbolizersOfOneProcessShareItsImage).Pointer())
	const want = "github.com/trentas/ptop/pkg/symbol.TestSymbolizersOfOneProcessShareItsImage"

	a, err := NewSymbolizer(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSymbolizer(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if fr := a.Symbolize(pc); fr.Func != want {
		t.Fatalf("Symbolize = %+v, want %s", fr, want)
	}
	if fr := b.Symbolize(pc); fr.Func != want {
		t.Fatalf("second Symbolize = %+v, want %s", fr, want)
	}

	seg, ok := a.segFor(pc)
	if !ok {
		t.Fatal("test function is in no mapped segment")
	}
	ma, mb := a.module(seg.path), b.module(seg.path)
	if ma == nil || ma.image != mb.image {
		t.Fatal("two Symbolizers of one process parsed its executable twice")
	}
	requireMapping(t, ma)
	if !within(ma.pclnData, ma.mapping) {
		t.Error("the executable's .gopclntab is a heap copy")
	}

	exe := openModuleAt(t, "/proc/self/exe", "/proc/self/exe")
	if exe.image != ma.image {
		t.Error("/proc/self/exe and the mapped path parsed the same executable twice")
	}
	if exe.Name() != "exe" || ma.Name() == "exe" {
		t.Errorf("names leaked between Modules: %q, %q", exe.Name(), ma.Name())
	}
}
