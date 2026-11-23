package tui

import (
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
)

func openFDs(n int) []collector.FDEntry {
	fds := make([]collector.FDEntry, n)
	for i := range fds {
		fds[i] = collector.FDEntry{FD: i, Type: "socket", Desc: "TCP 10.0.0.1:443"}
	}
	return fds
}

// TestFDAlertComparesWithTheLimit pins the F6 alert to the target's own soft
// RLIMIT_NOFILE. It used to fire above a fixed 20, so a process with 28 fds and
// a limit of 524288 read "close to the limit".
func TestFDAlertComparesWithTheLimit(t *testing.T) {
	cases := []struct {
		name  string
		open  int
		limit *collector.FDLimit
		want  string // substring of the alert; "" means no limit alert
	}{
		{"the reported case", 28, &collector.FDLimit{Soft: 524288, Hard: 524288}, ""},
		{"below the threshold", 819, &collector.FDLimit{Soft: 1024, Hard: 524288}, ""},
		{"at the threshold", 820, &collector.FDLimit{Soft: 1024, Hard: 524288}, "820/1024 fds open — 80% of limit"},
		{"at the limit", 1024, &collector.FDLimit{Soft: 1024, Hard: 524288}, "1024/1024 fds open — 100% of limit"},
		{"unlimited", 5000, &collector.FDLimit{Soft: collector.FDLimitUnlimited, Hard: collector.FDLimitUnlimited}, ""},
		{"limit unknown", 5000, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
			m.FDs = openFDs(tc.open)
			m.FDLimit = tc.limit
			out := renderFDAlerts(m)
			if tc.want == "" {
				if strings.Contains(out, "limit") {
					t.Fatalf("alert raised: %q", out)
				}
				return
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("alert %q, want it to contain %q", out, tc.want)
			}
		})
	}
}

// TestFDLimitReachesStats checks the limit travels from the bus to the Stats
// panel, and that an unknown one reads "—" rather than a number.
func TestFDLimitReachesStats(t *testing.T) {
	m := modelOnSet(t, procOnlySet())
	next, _ := m.Update(FDMsg(openFDs(28)))
	m = next.(Model)

	if got := renderFDStats(m, 40); !strings.Contains(got, "28 / —") {
		t.Errorf("Stats before any limit arrived:\n%s\nwant \"28 / —\"", got)
	}

	msg := busMsg(collector.FDLimit{Soft: 1024, Hard: 524288})
	if _, ok := msg.(FDLimitMsg); !ok {
		t.Fatalf("busMsg(FDLimit) = %T, want FDLimitMsg", msg)
	}
	next, _ = m.Update(msg)
	m = next.(Model)

	if m.FDLimit == nil || m.FDLimit.Soft != 1024 {
		t.Fatalf("model FDLimit = %+v, want soft 1024", m.FDLimit)
	}
	if got := renderFDStats(m, 40); !strings.Contains(got, "28 / 1024") {
		t.Errorf("Stats with a limit:\n%s\nwant \"28 / 1024\"", got)
	}
}

// TestFDTableShowsOnlyWhatWasRead checks the F6 columns that come from the
// file offset, and the ages of fds older than the capture.
func TestFDTableShowsOnlyWhatWasRead(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.FDs = []collector.FDEntry{
		{FD: 1, Type: "socket", Desc: "UNIX /run/systemd/journal/stdout", AgeMs: 30 * 60 * 1000, Preexisting: true},
		{FD: 3, Type: "file", Desc: "/var/log/app.log", Bytes: 4096, Active: true, PosKnown: true, AgeMs: 2000},
		{FD: 4, Type: "file", Desc: "/tmp/cache.bin", PosKnown: true, AgeMs: 25 * 60 * 1000, Preexisting: true},
		{FD: 5, Type: "other", Desc: "anon_inode:[pidfd]", AgeMs: 2000},
	}
	m.FDFilter = "all"

	rows := strings.Split(ansiRe.ReplaceAllString(renderFDTable(m, 120, 20), ""), "\n")
	row := func(desc string) string {
		for _, r := range rows {
			if strings.Contains(r, desc) {
				return r
			}
		}
		t.Fatalf("no row for %q in:\n%s", desc, strings.Join(rows, "\n"))
		return ""
	}
	if !strings.Contains(rows[0], "OFFSET") {
		t.Errorf("table header %q: the column is the file offset", rows[0])
	}
	if sock := row("journal/stdout"); !strings.Contains(sock, "—") || strings.Contains(sock, "○") || !strings.Contains(sock, "≥30m") {
		t.Errorf("socket row %q: offset and activity unmeasured (—), age a lower bound (≥30m)", sock)
	}
	if log := row("app.log"); strings.Contains(log, "—") || !strings.Contains(log, "●") {
		t.Errorf("file row %q: offset read and moving", log)
	}

	alerts := ansiRe.ReplaceAllString(renderFDAlerts(m), "")
	if !strings.Contains(alerts, "fd=4 /tmp file open ≥25m") || strings.Contains(alerts, "no activity") {
		t.Errorf("alerts %q: the /tmp file, its age as a lower bound, and no claim about activity", alerts)
	}

	stats := ansiRe.ReplaceAllString(renderFDStats(m, 40), "")
	for _, want := range []string{"Active files", "1 / 2", "≥30m"} {
		if !strings.Contains(stats, want) {
			t.Errorf("Stats missing %q:\n%s", want, stats)
		}
	}
	if strings.Contains(stats, "Total I/O") {
		t.Errorf("Stats sums file offsets as I/O:\n%s", stats)
	}

	// Darwin's shape: nothing has an offset.
	for i := range m.FDs {
		m.FDs[i].PosKnown, m.FDs[i].Active, m.FDs[i].Bytes = false, false, 0
	}
	if got := ansiRe.ReplaceAllString(renderFDStats(m, 40), ""); !strings.Contains(got, "Active files") || !strings.Contains(got, "—") {
		t.Errorf("Stats with no offset anywhere must read —:\n%s", got)
	}
}

// TestFDBreakdownListsEveryTypeBusiestFirst: every type the collectors emit
// has a bar and a filter, and the bars rank by count so the few rows the
// panel has go to the types that hold fds.
func TestFDBreakdownListsEveryTypeBusiestFirst(t *testing.T) {
	var fds []collector.FDEntry
	add := func(typ string, n int) {
		for i := 0; i < n; i++ {
			fds = append(fds, collector.FDEntry{FD: len(fds), Type: typ})
		}
	}
	add("file", 1)
	add("other", 300)
	add("event", 2)
	add("socket", 20)

	lines := strings.Split(ansiRe.ReplaceAllString(renderFDMini(fds, 40), ""), "\n")
	var order []string
	for _, l := range lines[1:] {
		order = append(order, strings.Fields(l)[0])
	}
	if got, want := strings.Join(order, ","), "other,socket,event,file"; got != want {
		t.Errorf("breakdown order %s, want %s (busiest first, empty types left out)", got, want)
	}

	for _, typ := range []string{"event", "other"} {
		found := false
		for _, f := range fdFilters {
			found = found || f == typ
		}
		if !found {
			t.Errorf("no filter for type %q: %v", typ, fdFilters)
		}
	}
}

// TestFDFilterRowSkipsEmptyTypes: at 140 columns the seven type chips did not
// fit, and an empty "pipe (0)" pushed out the chip holding most of the fds.
func TestFDFilterRowSkipsEmptyTypes(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.FDs = append(openFDs(20), collector.FDEntry{FD: 99, Type: "other", Desc: "anon_inode:[pidfd]"})
	m.FDFilter = "all"

	row := ansiRe.ReplaceAllString(renderFDFilterRow(m, 100), "")
	for _, want := range []string{"all (21)", "socket (20)", "other (1)"} {
		if !strings.Contains(row, want) {
			t.Errorf("filter row %q missing %q", row, want)
		}
	}
	if strings.Contains(row, "pipe (0)") {
		t.Errorf("filter row %q shows an empty type", row)
	}

	m.FDFilter = "timer"
	if row := ansiRe.ReplaceAllString(renderFDFilterRow(m, 100), ""); !strings.Contains(row, "timer (0)") {
		t.Errorf("filter row %q hides the active filter", row)
	}
}
