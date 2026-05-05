package collector

import "testing"

const sampleProcIO = `rchar: 1024000
wchar: 512000
syscr: 250
syscw: 100
read_bytes: 819200
write_bytes: 409600
cancelled_write_bytes: 0
`

func TestParseProcIO_basic(t *testing.T) {
	io, err := parseProcIO([]byte(sampleProcIO))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if io.rchar != 1024000 {
		t.Errorf("rchar=%d", io.rchar)
	}
	if io.wchar != 512000 {
		t.Errorf("wchar=%d", io.wchar)
	}
	if io.syscr != 250 {
		t.Errorf("syscr=%d", io.syscr)
	}
	if io.syscw != 100 {
		t.Errorf("syscw=%d", io.syscw)
	}
	if io.readBytes != 819200 {
		t.Errorf("readBytes=%d", io.readBytes)
	}
	if io.writeBytes != 409600 {
		t.Errorf("writeBytes=%d", io.writeBytes)
	}
}

func TestParseProcIO_extraWhitespace(t *testing.T) {
	// Algumas distros usam tab; algumas variantes têm espaço duplicado
	noisy := "rchar:\t1000\n  wchar:    2000  \nsyscr:50\n"
	io, err := parseProcIO([]byte(noisy))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if io.rchar != 1000 || io.wchar != 2000 || io.syscr != 50 {
		t.Errorf("parsing tolerante falhou: rchar=%d wchar=%d syscr=%d", io.rchar, io.wchar, io.syscr)
	}
}

func TestParseProcIO_malformed(t *testing.T) {
	if _, err := parseProcIO([]byte("garbage no colons")); err == nil {
		t.Error("esperava erro pra entrada sem pares chave:valor")
	}
}

func TestParseProcIO_unknownFieldsIgnored(t *testing.T) {
	mixed := "rchar: 100\nfuture_field: 999\nwchar: 200\n"
	io, err := parseProcIO([]byte(mixed))
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if io.rchar != 100 || io.wchar != 200 {
		t.Errorf("campos conhecidos não parseados: rchar=%d wchar=%d", io.rchar, io.wchar)
	}
}
