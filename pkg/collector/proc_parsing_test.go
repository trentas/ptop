//go:build linux

package collector

import "testing"

// Stat actually collected from a bash shell on Linux:
//   pid=12345 comm=(bash) state=S ppid=12340 ... utime=42 stime=18 ... minflt=1234 ... majflt=5
const sampleStat = `12345 (bash) S 12340 12345 12345 34816 12345 4194304 1234 0 5 0 42 18 0 0 20 0 1 0 88888 8454144 1024 18446744073709551615 1 1 0 0 0 0 0 0 65536 1 0 0 17 2 0 0 0 0 0 0 0 0 0 0 0 0 0`

// Stat with parens inside comm — real case for programs like "((sd-pam))":
const sampleStatTrickyComm = `12345 (sh) (((bad))) S 12340 12345 12345 0 0 0 99 0 7 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0`

func TestParseProcStatTimes_basic(t *testing.T) {
	utime, stime, minflt, majflt, blkio, err := parseProcStatTimes([]byte(sampleStat))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if utime != 42 {
		t.Errorf("utime=%d, expected 42", utime)
	}
	if stime != 18 {
		t.Errorf("stime=%d, expected 18", stime)
	}
	if minflt != 1234 {
		t.Errorf("minflt=%d, expected 1234", minflt)
	}
	if majflt != 5 {
		t.Errorf("majflt=%d, expected 5", majflt)
	}
	if blkio != 0 {
		// in sampleStat, post[39] = "0"
		t.Errorf("blkio=%d, expected 0 in sample", blkio)
	}
}

// Sample with field 42 (blkio) > 0 — set 99 at index post[39]:
//
//	pid (comm) state ppid pgrp session tty_nr tpgid flags
//	minflt cminflt majflt cmajflt utime stime cutime cstime
//	priority nice num_threads itrealvalue starttime vsize rss
//	rsslim startcode endcode startstack kstkesp kstkeip signal
//	blocked sigignore sigcatch wchan nswap cnswap exit_signal
//	processor rt_priority policy delayacct_blkio_ticks ...
const sampleStatWithBlkio = `12345 (myapp) R 1 1 1 0 -1 4194304 100 0 0 0 50 25 0 0 20 0 1 0 100 8454144 1024 ` +
	`18446744073709551615 1 1 0 0 0 0 0 0 65536 1 0 0 17 0 0 0 99 0 0 0 0 0 0 0 0 0`

func TestParseProcStatTimes_blkio(t *testing.T) {
	_, _, _, _, blkio, err := parseProcStatTimes([]byte(sampleStatWithBlkio))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if blkio != 99 {
		t.Errorf("blkio=%d, expected 99", blkio)
	}
}

// Old kernel (without CONFIG_TASK_DELAY_ACCT) or truncated before field 42 — must return blkio=0 with no error.
func TestParseProcStatTimes_shortNoBlkio(t *testing.T) {
	short := `12345 (proc) S 1 2 3 0 0 0 1 0 2 0 10 5 0 0 20 0 1 0`
	_, _, _, _, blkio, err := parseProcStatTimes([]byte(short))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blkio != 0 {
		t.Errorf("blkio must be 0 when the field is absent, got %d", blkio)
	}
}

func TestParseProcStatTimes_trickyComm(t *testing.T) {
	// Ensure the parser uses the LAST `)` and not the first
	utime, stime, _, majflt, _, err := parseProcStatTimes([]byte(sampleStatTrickyComm))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if utime != 100 || stime != 200 {
		t.Errorf("wrong utime/stime: %d/%d", utime, stime)
	}
	if majflt != 7 {
		t.Errorf("majflt=%d, expected 7", majflt)
	}
}

func TestParseProcStatTimes_malformed(t *testing.T) {
	if _, _, _, _, _, err := parseProcStatTimes([]byte("garbage no parens here")); err == nil {
		t.Error("expected error for input without ')'")
	}
	if _, _, _, _, _, err := parseProcStatTimes([]byte("123 (x) S")); err == nil {
		t.Error("expected error for input with too few fields")
	}
}

func TestParseThreadStat_basic(t *testing.T) {
	comm, state, ticks, ok := parseThreadStat([]byte(sampleStat))
	if !ok {
		t.Fatal("parser failed on valid input")
	}
	if comm != "bash" {
		t.Errorf("comm=%q, expected bash", comm)
	}
	if state != 'S' {
		t.Errorf("state=%c, expected S", state)
	}
	if ticks != 60 { // 42 + 18
		t.Errorf("ticks=%d, expected 60", ticks)
	}
}

func TestParseThreadStat_trickyComm(t *testing.T) {
	comm, state, ticks, ok := parseThreadStat([]byte(sampleStatTrickyComm))
	if !ok {
		t.Fatal("parser failed")
	}
	// Comm must include everything between the first `(` and the last `)`
	expected := "sh) (((bad))"
	if comm != expected {
		t.Errorf("comm=%q, expected %q", comm, expected)
	}
	if state != 'S' {
		t.Errorf("state=%c, expected S", state)
	}
	if ticks != 300 {
		t.Errorf("ticks=%d, expected 300", ticks)
	}
}

func TestMapThreadState(t *testing.T) {
	cases := map[byte]string{
		'R': "running",
		'D': "blocked",
		'S': "sleeping",
		'I': "sleeping",
		'Z': "stopped",
		'T': "stopped",
		'?': "unknown",
	}
	for c, want := range cases {
		if got := mapThreadState(c); got != want {
			t.Errorf("mapThreadState(%c)=%q, expected %q", c, got, want)
		}
	}
}
