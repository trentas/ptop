package serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// --- certificate fixtures -------------------------------------------------
//
// Everything is generated in-process: a CA, a server leaf with a 127.0.0.1 IP
// SAN (the tests dial by IP) and client leaves. No checked-in key material, and
// nothing expires on us.

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue signs a leaf certificate and returns its PEM cert and key bytes.
func (ca *testCA) issue(t *testing.T, cn string, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// writePEM drops bytes into dir/name and returns the path.
func writePEM(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// serverFiles issues a server keypair from ca and writes cert/key/CA to dir.
func serverFiles(t *testing.T, ca *testCA, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, "ptop-server", true)
	return writePEM(t, dir, "server.crt", certPEM),
		writePEM(t, dir, "server.key", keyPEM),
		writePEM(t, dir, "ca.crt", ca.certPEM)
}

// clientCreds wraps clientTLSConfig as gRPC transport credentials.
func clientCreds(t *testing.T, ca *testCA, certCA *testCA) credentials.TransportCredentials {
	t.Helper()
	return credentials.NewTLS(clientTLSConfig(t, ca, certCA))
}

// clientTLSConfig builds a client-side tls.Config trusting ca, optionally
// presenting a certificate issued by certCA (nil = no client certificate).
func clientTLSConfig(t *testing.T, ca *testCA, certCA *testCA) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.certPEM) {
		t.Fatal("client pool: no cert in CA PEM")
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if certCA != nil {
		certPEM, keyPEM := certCA.issue(t, "witness", false)
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("client keypair: %v", err)
		}
		// GetClientCertificate, not Certificates: with Certificates the Go client
		// silently withholds a certificate whose issuer is not in the server's
		// advertised CA list, so an untrusted cert would look like "no cert at
		// all" and the server-side verification would never run. Forcing the send
		// is what puts RequireAndVerifyClientCert under test.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &pair, nil
		}
	}
	return cfg
}

// tlsHandshakeErr dials target and reads one byte, returning the error the
// server ends the connection with.
//
// Reading is the point: under TLS 1.3 the client finishes its side of the
// handshake before the server has judged the client certificate, so tls.Dial
// itself usually succeeds and the server's alert only lands on the next read.
// Through gRPC the same rejection surfaces as whatever operation happens to
// lose the race — a plain "broken pipe" on the request write, on Linux — so the
// *reason* for a refusal is asserted here instead.
func tlsHandshakeErr(t *testing.T, target string, cfg *tls.Config) error {
	t.Helper()
	conn, err := tls.Dial("tcp", target, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, err = conn.Read(make([]byte, 1))
	return err
}

// --- the server under test ------------------------------------------------

// startTCPServer brings up a real gRPC server on 127.0.0.1:0 through the same
// runServer path Run uses, with credentials resolved by serverCredentials from
// opts, and a fake collector emitting CPU samples. It returns the dial target.
func startTCPServer(ctx context.Context, t *testing.T, opts TLSOptions) string {
	t.Helper()
	addr := "tcp://127.0.0.1:0"

	creds, _, err := serverCredentials(addr, opts)
	if err != nil {
		t.Fatalf("serverCredentials: %v", err)
	}
	lis, cleanup, err := listen(addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(cleanup)

	f := newFake(64)
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				select {
				case f.ch <- collector.CpuSample{UsagePct: 42, Timestamp: time.Now()}:
				default:
				}
			}
		}
	}()

	target := lis.Addr().String()
	done := make(chan error, 1)
	go func() {
		done <- runServer(ctx, lis, creds, "test", 4242, []collector.Collector{f}, nil, Options{})
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("runServer did not return after cancel")
		}
	})
	return target
}

// firstEvent subscribes and returns the first event, or the error that stopped
// it. Used both for the success path and for the handshake-refusal paths, where
// the failure surfaces on Subscribe or on the first Recv depending on timing.
func firstEvent(ctx context.Context, target string, creds credentials.TransportCredentials) (*pb.Event, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	recvCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stream, err := pb.NewEventStreamServiceClient(conn).Subscribe(recvCtx, &pb.SubscribeRequest{})
	if err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetEvent(), nil
}

// A subscriber presenting a certificate from the trusted CA streams events
// end-to-end over mTLS — the acceptance case of #95.
func TestServeMTLSEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t, "ptop-test-ca")
	dir := t.TempDir()
	cert, key, caPath := serverFiles(t, ca, dir)

	target := startTCPServer(ctx, t, TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: caPath})

	ev, err := firstEvent(ctx, target, clientCreds(t, ca, ca))
	if err != nil {
		t.Fatalf("mTLS subscriber failed: %v", err)
	}
	if ev == nil || ev.GetCategory() != pb.Category_CATEGORY_CPU {
		t.Fatalf("unexpected first event: %v", ev)
	}
	if ev.GetPid() != 4242 {
		t.Errorf("pid = %d, want 4242", ev.GetPid())
	}
}

// With --serve-tls-client-ca, a client that presents no certificate must be
// refused: that is the difference between mTLS and plain server-side TLS.
func TestServeMTLSRejectsClientWithoutCert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t, "ptop-test-ca")
	cert, key, caPath := serverFiles(t, ca, t.TempDir())
	target := startTCPServer(ctx, t, TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: caPath})

	if ev, err := firstEvent(ctx, target, clientCreds(t, ca, nil)); err == nil {
		t.Fatalf("subscriber without a client certificate was served: got event %v", ev)
	}
	err := tlsHandshakeErr(t, target, clientTLSConfig(t, ca, nil))
	if err == nil {
		t.Fatal("TLS connection without a client certificate stayed open")
	}
	if !strings.Contains(err.Error(), "certificate required") {
		t.Errorf("error = %q, want the server to demand a client certificate", err)
	}
}

// A client certificate signed by some other CA is not a client certificate.
func TestServeMTLSRejectsUntrustedClientCert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t, "ptop-test-ca")
	rogue := newTestCA(t, "rogue-ca")
	cert, key, caPath := serverFiles(t, ca, t.TempDir())
	target := startTCPServer(ctx, t, TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: caPath})

	if ev, err := firstEvent(ctx, target, clientCreds(t, ca, rogue)); err == nil {
		t.Fatalf("client certificate from an untrusted CA was accepted: got event %v", ev)
	}
	// The certificate is sent (see clientTLSConfig) and rejected by the server's
	// RequireAndVerifyClientCert against ClientCAs — not withheld by the client.
	err := tlsHandshakeErr(t, target, clientTLSConfig(t, ca, rogue))
	if err == nil {
		t.Fatal("TLS connection with an untrusted client certificate stayed open")
	}
	if !strings.Contains(err.Error(), "unknown certificate authority") {
		t.Errorf("error = %q, want rejection by the server's client CA", err)
	}
}

// A plaintext client gets nothing out of a TLS endpoint (the inverse of the
// exposure #95 is about: no accidental cleartext fallback).
func TestServeTLSRefusesPlaintextClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t, "ptop-test-ca")
	cert, key, _ := serverFiles(t, ca, t.TempDir())
	target := startTCPServer(ctx, t, TLSOptions{CertFile: cert, KeyFile: key})

	// The exact transport error here is platform-dependent (the server drops the
	// connection mid-handshake), so only the refusal itself is asserted.
	if ev, err := firstEvent(ctx, target, insecure.NewCredentials()); err == nil {
		t.Fatalf("plaintext client was served by a TLS endpoint: got event %v", ev)
	}
}

// --serve-insecure still works, so the opt-in is a real escape hatch.
func TestServeInsecureTCPStillStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	target := startTCPServer(ctx, t, TLSOptions{AllowInsecure: true})
	ev, err := firstEvent(ctx, target, insecure.NewCredentials())
	if err != nil {
		t.Fatalf("plaintext subscriber failed with --serve-insecure: %v", err)
	}
	if ev.GetCategory() != pb.Category_CATEGORY_CPU {
		t.Fatalf("unexpected first event: %v", ev)
	}
}

// --- policy table ---------------------------------------------------------

func TestServerCredentialsPolicy(t *testing.T) {
	ca := newTestCA(t, "ptop-test-ca")
	dir := t.TempDir()
	cert, key, caPath := serverFiles(t, ca, dir)
	notPEM := writePEM(t, dir, "garbage.crt", []byte("not a certificate\n"))

	const tcp, unix = "tcp://127.0.0.1:50051", "unix:///tmp/ptop.sock"

	cases := []struct {
		name     string
		addr     string
		opts     TLSOptions
		wantMode string // "" = expect an error
		wantErr  string // substring, checked when wantMode == ""
	}{
		{name: "unix bare", addr: unix, wantMode: modeUnix},
		{name: "unix with cert", addr: unix, opts: TLSOptions{CertFile: cert, KeyFile: key},
			wantErr: "unix socket"},
		{name: "unix with insecure", addr: unix, opts: TLSOptions{AllowInsecure: true},
			wantErr: "cleartext TCP"},

		{name: "tcp bare is refused", addr: tcp, wantErr: "refusing to serve"},
		{name: "tcp opt-in plaintext", addr: tcp, opts: TLSOptions{AllowInsecure: true},
			wantMode: modePlaintext},
		{name: "tcp tls", addr: tcp, opts: TLSOptions{CertFile: cert, KeyFile: key},
			wantMode: modeTLS},
		{name: "tcp mtls", addr: tcp, opts: TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: caPath},
			wantMode: modeMTLS},

		{name: "cert without key", addr: tcp, opts: TLSOptions{CertFile: cert},
			wantErr: "needs --serve-tls-key"},
		{name: "key without cert", addr: tcp, opts: TLSOptions{KeyFile: key},
			wantErr: "needs --serve-tls-cert"},
		{name: "client ca alone", addr: tcp, opts: TLSOptions{ClientCAFile: caPath},
			wantErr: "requires --serve-tls-cert"},
		{name: "tls plus insecure contradict", addr: tcp,
			opts:    TLSOptions{CertFile: cert, KeyFile: key, AllowInsecure: true},
			wantErr: "contradicts"},

		{name: "missing cert file", addr: tcp,
			opts:    TLSOptions{CertFile: filepath.Join(dir, "nope.crt"), KeyFile: key},
			wantErr: "load tls keypair"},
		{name: "missing client ca file", addr: tcp,
			opts:    TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: filepath.Join(dir, "nope.crt")},
			wantErr: "read client CA"},
		{name: "client ca without a certificate in it", addr: tcp,
			opts:    TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: notPEM},
			wantErr: "no certificate found"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds, mode, err := serverCredentials(tc.addr, tc.opts)
			if tc.wantMode == "" {
				if err == nil {
					t.Fatalf("serverCredentials = mode %q, want error containing %q", mode, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("serverCredentials: %v", err)
			}
			if mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", mode, tc.wantMode)
			}
			if creds == nil {
				t.Error("credentials are nil")
			}
		})
	}
}

// --- rotation -------------------------------------------------------------

// rewrite replaces a PEM file's contents and pushes its modification time
// forward. The push is what makes the test deterministic: the reloader
// fingerprints files by size and mtime, and a test rewriting a same-sized file
// within one filesystem timestamp tick would otherwise look unchanged.
func rewrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// servedLeaf handshakes with the server and returns the certificate it
// presented.
func servedLeaf(t *testing.T, target string, cfg *tls.Config) *x509.Certificate {
	t.Helper()
	conn, err := tls.Dial("tcp", target, cfg)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("server presented no certificate")
	}
	return certs[0]
}

// A certificate rotated on disk is picked up on the next handshake — no
// restart, which is the point for a long-running process whose cert-manager
// secret rotates under it.
func TestServeTLSReloadsRotatedCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t, "ptop-test-ca")
	cert, key, _ := serverFiles(t, ca, t.TempDir())
	target := startTCPServer(ctx, t, TLSOptions{CertFile: cert, KeyFile: key})

	before := servedLeaf(t, target, clientTLSConfig(t, ca, nil))

	certPEM, keyPEM := ca.issue(t, "ptop-server-rotated", true)
	rewrite(t, cert, certPEM)
	rewrite(t, key, keyPEM)

	after := servedLeaf(t, target, clientTLSConfig(t, ca, nil))
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatal("server still presents the pre-rotation certificate")
	}
	if got := after.Subject.CommonName; got != "ptop-server-rotated" {
		t.Errorf("served certificate CN = %q, want the rotated one", got)
	}
}

// A torn or invalid write must not take the endpoint down: the last good
// material keeps serving. Losing every subscriber because a key was caught
// half-written would be a worse failure than the stale certificate.
func TestServeTLSKeepsLastGoodOnBrokenRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t, "ptop-test-ca")
	cert, key, _ := serverFiles(t, ca, t.TempDir())
	target := startTCPServer(ctx, t, TLSOptions{CertFile: cert, KeyFile: key})

	before := servedLeaf(t, target, clientTLSConfig(t, ca, nil))
	rewrite(t, cert, []byte("-----BEGIN CERTIFICATE-----\ntruncated"))

	after := servedLeaf(t, target, clientTLSConfig(t, ca, nil))
	if after.SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Error("served certificate changed after a broken rotation")
	}

	// And a later good write is still adopted — the reloader is not stuck on the
	// failure it reported.
	certPEM, keyPEM := ca.issue(t, "ptop-server-recovered", true)
	rewrite(t, cert, certPEM)
	rewrite(t, key, keyPEM)

	recovered := servedLeaf(t, target, clientTLSConfig(t, ca, nil))
	if got := recovered.Subject.CommonName; got != "ptop-server-recovered" {
		t.Errorf("served certificate CN = %q, want the recovered one", got)
	}
}

// The client CA bundle rotates too: a subscriber whose CA was not trusted is
// refused, and accepted once the bundle names its CA — same running server.
func TestServeMTLSReloadsClientCA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := newTestCA(t, "ptop-test-ca")
	next := newTestCA(t, "ptop-next-ca")
	cert, key, caPath := serverFiles(t, ca, t.TempDir())
	target := startTCPServer(ctx, t, TLSOptions{CertFile: cert, KeyFile: key, ClientCAFile: caPath})

	err := tlsHandshakeErr(t, target, clientTLSConfig(t, ca, next))
	if err == nil || !strings.Contains(err.Error(), "unknown certificate authority") {
		t.Fatalf("error = %v, want the not-yet-trusted client CA to be refused", err)
	}

	rewrite(t, caPath, next.certPEM)

	ev, err := firstEvent(ctx, target, clientCreds(t, ca, next))
	if err != nil {
		t.Fatalf("subscriber refused after its CA was added to the bundle: %v", err)
	}
	if ev.GetCategory() != pb.Category_CATEGORY_CPU {
		t.Fatalf("unexpected first event: %v", ev)
	}
}
