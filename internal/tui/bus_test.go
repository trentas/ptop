package tui

import (
	"context"
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trentas/ptop/pkg/collector"
)

// busFake is a Collector the test publishes on directly.
type busFake struct{ ch chan interface{} }

func newBusFake() *busFake { return &busFake{ch: make(chan interface{}, 64)} }

func (f *busFake) Start(int) error               { return nil }
func (f *busFake) Stop()                         {}
func (f *busFake) Subscribe() <-chan interface{} { return f.ch }

// feedFor wires a model onto collectors the test drives, the way --serve --tui
// hands the model a feed someone else started.
func feedFor(t *testing.T, cols ...collector.Collector) (*collector.Feed, Model) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	feed := &collector.Feed{
		Set: collector.NewSet(collector.SetConfig{}),
		Bus: collector.StartBus(ctx, cols),
	}
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true, Feed: feed})
	return feed, m
}

// One consumer, every collector: the model's single bus reader turns each
// published value into the message the Update switch already handles.
func TestBusMsgCoversEveryConsumedValue(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want tea.Msg
	}{
		{"cpu", collector.CpuSample{UsagePct: 3}, CpuMsg(collector.CpuSample{UsagePct: 3})},
		{"threads", []collector.ThreadInfo{{TID: 9}}, ThreadsMsg([]collector.ThreadInfo{{TID: 9}})},
		{"fds", []collector.FDEntry{{FD: 4}}, FDMsg([]collector.FDEntry{{FD: 4}})},
		{"fd event", collector.FDEvent{Message: "open"}, FDEventMsg(collector.FDEvent{Message: "open"})},
		{"syscalls", map[string]uint64{"read": 2}, SyscallsMsg(map[string]uint64{"read": 2})},
		{"net", []collector.NetConn{{FD: 5}}, NetMsg([]collector.NetConn{{FD: 5}})},
		{"locks", []collector.LockEntry{{UAddr: 1}}, LockGraphMsg([]collector.LockEntry{{UAddr: 1}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := busMsg(tc.in)
			if got == nil {
				t.Fatalf("busMsg(%T) = nil, want %T", tc.in, tc.want)
			}
			if gotT, wantT := fmt.Sprintf("%T", got), fmt.Sprintf("%T", tc.want); gotT != wantT {
				t.Errorf("busMsg(%T) = %s, want %s", tc.in, gotT, wantT)
			}
		})
	}

	// Both futex and the fd collector publish TimelineEvents; with one bus the
	// value's own type is what identifies it, so they map to the same message.
	if _, ok := busMsg(collector.TimelineEvent{Category: "lock"}).(TimelineMsg); !ok {
		t.Error("a lock TimelineEvent should map to TimelineMsg like any other")
	}

	// The per-allocation flood has no panel: skipping it here is what keeps it
	// from waking Update thousands of times a second.
	if msg := busMsg(collector.HeapEvent{Op: "malloc"}); msg != nil {
		t.Errorf("busMsg(HeapEvent) = %T, want nil (no panel renders it)", msg)
	}
}

// The model must consume through the bus, so what it reads is not taken away
// from the other consumers of the same collectors.
func TestModelConsumesSharedFeed(t *testing.T) {
	f := newBusFake()
	feed, m := feedFor(t, f)

	// A second consumer standing in for the gRPC stream.
	other := feed.Bus.Subscribe(16)
	defer other.Close()

	f.ch <- collector.CpuSample{UsagePct: 42}

	msg := m.waitBus()()
	cpu, ok := msg.(CpuMsg)
	if !ok || cpu.UsagePct != 42 {
		t.Fatalf("model received %#v, want CpuMsg{42}", msg)
	}
	select {
	case v := <-other.C():
		if s, ok := v.(collector.CpuSample); !ok || s.UsagePct != 42 {
			t.Fatalf("other consumer received %#v, want CpuSample{42}", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the model stole the value from the other consumer")
	}
}

// Quitting the TUI must not take the stream down with it: the model closes its
// own subscription and leaves collectors it did not start alone.
func TestModelCloseLeavesAHandedInFeedRunning(t *testing.T) {
	f := newBusFake()
	feed, m := feedFor(t, f)

	server := feed.Bus.Subscribe(16)
	defer server.Close()

	m.Close()

	f.ch <- collector.CpuSample{UsagePct: 7}
	select {
	case v := <-server.C():
		if s, ok := v.(collector.CpuSample); !ok || s.UsagePct != 7 {
			t.Fatalf("server received %#v, want CpuSample{7}", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the feed stopped when the TUI closed")
	}
	if m.ownsFeed {
		t.Error("model claims ownership of a feed it was handed")
	}
}

// A model that started its own feed keeps working exactly as before.
func TestModelOwnsItsFeedByDefault(t *testing.T) {
	m := NewModel(Config{PID: 0, FPS: 5, NoEBPF: true})
	if !m.ownsFeed {
		t.Fatal("a model with no Feed in its Config must own the one it starts")
	}
	if m.busSub == nil {
		t.Fatal("model has no bus subscription")
	}
	m.Close()
}

// waitBus reports the end of the feed rather than spinning on a closed channel.
func TestWaitBusOnClosedFeed(t *testing.T) {
	f := newBusFake()
	_, m := feedFor(t, f)
	m.busSub.Close()
	if _, ok := m.waitBus()().(busClosedMsg); !ok {
		t.Error("waitBus on a closed subscription should report busClosedMsg")
	}
}
