package serve

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSOptions configures the transport security of a `tcp://` --serve endpoint
// (issue #95). The zero value means "no TLS configured", which is only allowed
// for a unix socket or with AllowInsecure explicitly set.
//
// A unix socket needs none of this: it never leaves the host and listen()
// already restricts it to its owner (0600). TCP is the exposed case — the
// stream carries heap call sites, filesystem paths and, with --tls-bytes, TLS
// plaintext of the target, so cleartext on the wire has to be a decision
// instead of the default.
type TLSOptions struct {
	// CertFile and KeyFile are the server's PEM certificate and private key.
	// Set both to serve TLS.
	CertFile string
	KeyFile  string

	// ClientCAFile is a PEM CA bundle. When set, clients must present a
	// certificate signed by it — that is the mTLS mode.
	ClientCAFile string

	// AllowInsecure opts into a plaintext TCP listener. Without it, a `tcp://`
	// address and no certificate is an error, not a silent downgrade.
	AllowInsecure bool
}

// configured reports whether any certificate path was given.
func (o TLSOptions) configured() bool {
	return o.CertFile != "" || o.KeyFile != "" || o.ClientCAFile != ""
}

// Transport modes reported by serverCredentials, for the startup log line.
const (
	modeUnix      = "unix socket, owner-only"
	modeTLS       = "TLS"
	modeMTLS      = "mTLS, client certificate required"
	modePlaintext = "PLAINTEXT — cleartext on the wire"
)

// serverCredentials turns addr + o into the gRPC transport credentials to serve
// with, plus a short human-readable mode for the startup log. It is the policy
// gate for issue #95: TLS material belongs to tcp:// endpoints, a tcp://
// endpoint without it must be opted into, and contradictory flags fail here
// rather than resolving to whichever one the code happens to read first.
//
// It is called before the listener is created, so a bad certificate path fails
// before anything is bound.
func serverCredentials(addr string, o TLSOptions) (credentials.TransportCredentials, string, error) {
	if strings.HasPrefix(addr, "unix://") {
		if o.configured() {
			return nil, "", fmt.Errorf(
				"serve: --serve-tls-* configures a tcp:// endpoint, but %q is a unix socket "+
					"(already restricted to its owner, 0600) — drop the TLS flags or serve on tcp://", addr)
		}
		if o.AllowInsecure {
			return nil, "", fmt.Errorf(
				"serve: --serve-insecure is about cleartext TCP, but %q is a unix socket — drop the flag", addr)
		}
		return insecure.NewCredentials(), modeUnix, nil
	}

	switch {
	case o.CertFile != "" && o.KeyFile == "":
		return nil, "", errors.New("serve: --serve-tls-cert needs --serve-tls-key")
	case o.KeyFile != "" && o.CertFile == "":
		return nil, "", errors.New("serve: --serve-tls-key needs --serve-tls-cert")
	case o.CertFile == "" && o.ClientCAFile != "":
		return nil, "", errors.New(
			"serve: --serve-tls-client-ca requires --serve-tls-cert/--serve-tls-key — " +
				"verifying client certificates still needs a server certificate")
	case o.CertFile != "" && o.AllowInsecure:
		return nil, "", errors.New(
			"serve: --serve-insecure contradicts --serve-tls-cert — pick cleartext or TLS, not both")
	case o.CertFile == "" && !o.AllowInsecure:
		return nil, "", fmt.Errorf(
			"serve: refusing to serve %s in cleartext — the stream carries process internals "+
				"(heap call sites, filesystem paths, and TLS plaintext with --tls-bytes). "+
				"Pass --serve-tls-cert/--serve-tls-key (add --serve-tls-client-ca for mTLS), "+
				"or --serve-insecure to accept cleartext deliberately", addr)
	case o.CertFile == "":
		return insecure.NewCredentials(), modePlaintext, nil
	}

	// Load once here so a bad path, an unreadable key or an empty CA bundle is a
	// startup error rather than a handshake-time surprise.
	r := &tlsReloader{opts: o}
	if _, err := r.current(); err != nil {
		return nil, "", err
	}

	mode := modeTLS
	if o.ClientCAFile != "" {
		mode = modeMTLS
	}

	// GetConfigForClient, not a fixed Certificates list: the config is rebuilt
	// from disk whenever the files change, so rotating certificates (or the
	// client CA bundle) does not need a restart.
	return credentials.NewTLS(&tls.Config{
		MinVersion:         tls.VersionTLS12,
		GetConfigForClient: r.configForClient,
	}), mode, nil
}

// tlsReloader keeps the server's TLS config in sync with the files it was built
// from. A long-running ptop outlives its certificate: cert-manager and friends
// rotate the secret under the process, and without this the endpoint would keep
// presenting the expired material until someone restarted the pod.
type tlsReloader struct {
	opts TLSOptions

	mu    sync.Mutex
	stamp string      // identity of the files behind cur
	cur   *tls.Config // last successfully built config
}

// configForClient is the tls.Config.GetConfigForClient hook: it runs once per
// handshake, which is where a rotation gets noticed.
func (r *tlsReloader) configForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	return r.current()
}

// current returns the cached config, rebuilding it when the files changed.
func (r *tlsReloader) current() (*tls.Config, error) {
	stamp := r.fingerprint()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil && stamp == r.stamp {
		return r.cur, nil
	}

	cfg, err := buildServerTLSConfig(r.opts)
	if err != nil {
		if r.cur == nil {
			return nil, err // startup: nothing to fall back to
		}
		// Mid-flight the files can be briefly inconsistent (a half-written key,
		// a cert swapped a moment before its key). Dropping the endpoint over
		// that would be worse than serving the material that still works, so
		// keep the last good config and say so. Adopting the stamp keeps this to
		// one line per broken state instead of one per handshake.
		fmt.Fprintf(os.Stderr, "[ptop] TLS material changed but does not load (%v) — still serving the previous certificate\n", err)
		r.stamp = stamp
		return r.cur, nil
	}

	if r.cur != nil {
		fmt.Fprintln(os.Stderr, "[ptop] reloaded TLS material after a change on disk")
	}
	r.cur, r.stamp = cfg, stamp
	return cfg, nil
}

// fingerprint identifies the current TLS files by size and modification time.
// A content hash would be exact, but this runs on every handshake while
// rotation happens on the order of hours — three stat calls is the right price.
// A missing file gets its own marker so the reload retries once it reappears.
func (r *tlsReloader) fingerprint() string {
	var b strings.Builder
	for _, f := range []string{r.opts.CertFile, r.opts.KeyFile, r.opts.ClientCAFile} {
		if f == "" {
			continue
		}
		fi, err := os.Stat(f)
		if err != nil {
			fmt.Fprintf(&b, "%s:absent;", f)
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", f, fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

// buildServerTLSConfig reads the certificate (and client CA bundle, for mTLS)
// off disk into a server tls.Config.
func buildServerTLSConfig(o TLSOptions) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("serve: load tls keypair: %w", err)
	}

	// TLS 1.2 floor: 1.0/1.1 are deprecated (RFC 8996), while Go's 1.2 defaults
	// already offer only AEAD suites with forward secrecy. Requiring 1.3 would
	// buy little here and lock out consumers on older gRPC stacks.
	//
	// NextProtos has to be set here too: a config returned by
	// GetConfigForClient replaces the outer one wholesale, including the "h2"
	// ALPN protocol gRPC put there — and a gRPC client that cannot negotiate h2
	// is refused.
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}

	if o.ClientCAFile != "" {
		pem, err := os.ReadFile(o.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("serve: read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("serve: no certificate found in client CA %q", o.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}
