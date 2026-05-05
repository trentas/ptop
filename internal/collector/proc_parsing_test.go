package collector

import "testing"

// Stat real coletado de um shell bash em Linux:
//   pid=12345 comm=(bash) state=S ppid=12340 ... utime=42 stime=18 ... minflt=1234 ... majflt=5
const sampleStat = `12345 (bash) S 12340 12345 12345 34816 12345 4194304 1234 0 5 0 42 18 0 0 20 0 1 0 88888 8454144 1024 18446744073709551615 1 1 0 0 0 0 0 0 65536 1 0 0 17 2 0 0 0 0 0 0 0 0 0 0 0 0 0`

// Stat com parens dentro do comm — caso real para programas tipo "((sd-pam))":
const sampleStatTrickyComm = `12345 (sh) (((bad))) S 12340 12345 12345 0 0 0 99 0 7 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0`

func TestParseProcStatTimes_basic(t *testing.T) {
	utime, stime, minflt, majflt, err := parseProcStatTimes([]byte(sampleStat))
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if utime != 42 {
		t.Errorf("utime=%d, esperado 42", utime)
	}
	if stime != 18 {
		t.Errorf("stime=%d, esperado 18", stime)
	}
	if minflt != 1234 {
		t.Errorf("minflt=%d, esperado 1234", minflt)
	}
	if majflt != 5 {
		t.Errorf("majflt=%d, esperado 5", majflt)
	}
}

func TestParseProcStatTimes_trickyComm(t *testing.T) {
	// Garante que o parser usa o ÚLTIMO `)` e não o primeiro
	utime, stime, _, majflt, err := parseProcStatTimes([]byte(sampleStatTrickyComm))
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if utime != 100 || stime != 200 {
		t.Errorf("utime/stime errados: %d/%d", utime, stime)
	}
	if majflt != 7 {
		t.Errorf("majflt=%d, esperado 7", majflt)
	}
}

func TestParseProcStatTimes_malformed(t *testing.T) {
	if _, _, _, _, err := parseProcStatTimes([]byte("garbage no parens here")); err == nil {
		t.Error("esperava erro pra entrada sem ')'")
	}
	if _, _, _, _, err := parseProcStatTimes([]byte("123 (x) S")); err == nil {
		t.Error("esperava erro pra entrada com poucos campos")
	}
}

func TestParseThreadStat_basic(t *testing.T) {
	comm, state, ticks, ok := parseThreadStat([]byte(sampleStat))
	if !ok {
		t.Fatal("parser falhou em entrada válida")
	}
	if comm != "bash" {
		t.Errorf("comm=%q, esperado bash", comm)
	}
	if state != 'S' {
		t.Errorf("state=%c, esperado S", state)
	}
	if ticks != 60 { // 42 + 18
		t.Errorf("ticks=%d, esperado 60", ticks)
	}
}

func TestParseThreadStat_trickyComm(t *testing.T) {
	comm, state, ticks, ok := parseThreadStat([]byte(sampleStatTrickyComm))
	if !ok {
		t.Fatal("parser falhou")
	}
	// Comm deve incluir tudo entre primeiro `(` e último `)`
	expected := "sh) (((bad))"
	if comm != expected {
		t.Errorf("comm=%q, esperado %q", comm, expected)
	}
	if state != 'S' {
		t.Errorf("state=%c, esperado S", state)
	}
	if ticks != 300 {
		t.Errorf("ticks=%d, esperado 300", ticks)
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
			t.Errorf("mapThreadState(%c)=%q, esperado %q", c, got, want)
		}
	}
}
