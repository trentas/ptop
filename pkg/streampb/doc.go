// Package streampb holds the generated protobuf bindings for ptop's event
// stream (proto package ptop.v1, defined in proto/event.proto).
//
// It is the versioned wire contract external consumers pin to (#51): the
// collector publishes a stream of Event messages, each an envelope (time,
// pid/tid, category, optional stack reference) wrapping one category-specific
// payload in its oneof. The gRPC service and the collector→Event mapping live
// in separate packages; this one is pure schema.
//
// Regenerate with `make proto` after editing proto/event.proto. The generated
// event.pb.go is committed so `go build` and releases need no protobuf
// toolchain.
package streampb
