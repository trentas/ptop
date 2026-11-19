package bpf

// Who opened a connection, as the network program records it (#195).
// Build-tag-free: the collector converts the tracer's rows in both builds.

// NetOrigin is who opened a connection, as far as the tracer saw.
type NetOrigin uint8

const (
	// NetOriginUnknown: the tracer did not see the open. The connection is
	// older than the capture, another process connected it and handed it
	// over, or its passive open's note aged out before the target touched it.
	// Never read it as either of the others.
	NetOriginUnknown NetOrigin = iota
	// NetOriginConnected: an active open; the target called connect() on it.
	NetOriginConnected
	// NetOriginAccepted: a passive open; a listener's child the target owns,
	// which it got by accept().
	NetOriginAccepted
)
