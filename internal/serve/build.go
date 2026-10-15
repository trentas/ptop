package serve

import pb "github.com/trentas/ptop/pkg/streampb"

// PtopBuild identifies the ptop binary serving the stream (#145). Every field
// is "" when unknown.
//
// It rides in the handshake because the meaning of a field changes between
// releases in ways the wire alone does not show — until v1.8.1 a connection's
// latency_ms was never a measurement (#144), a syscall's latency_ns was always
// 0 (#143) — and a consumer comparing two captures has to know which side of
// such a change each one is on.
type PtopBuild struct {
	Version   string // release tag; else Go's VCS-derived version, or "dev"
	Commit    string // git revision, "+dirty" when built from a modified tree
	BuildDate string // RFC 3339
}

// wire renders the identity for the handshake: nil when nothing is known, so
// the field is absent rather than present and empty.
func (b PtopBuild) wire() *pb.PtopBuild {
	if b == (PtopBuild{}) {
		return nil
	}
	return &pb.PtopBuild{Version: b.Version, Commit: b.Commit, BuildDate: b.BuildDate}
}
