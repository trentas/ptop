package serve

import "testing"

// Unknown is absent, not present-and-empty: a consumer reads a missing field
// as "a server older than this field / nothing known", and an empty message
// would claim to know something.
func TestPtopBuildWireUnknownIsAbsent(t *testing.T) {
	if w := (PtopBuild{}).wire(); w != nil {
		t.Errorf("zero build rendered as %v, want nil", w)
	}
	if w := (PtopBuild{Commit: "abc"}).wire(); w.GetCommit() != "abc" || w.GetVersion() != "" {
		t.Errorf("partial build rendered as %v", w)
	}
}
