package serve

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

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

	cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("serve: load tls keypair: %w", err)
	}
	// TLS 1.2 floor: 1.0/1.1 are deprecated (RFC 8996), while Go's 1.2 defaults
	// already offer only AEAD suites with forward secrecy. Requiring 1.3 would
	// buy little here and lock out consumers on older gRPC stacks.
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	mode := modeTLS

	if o.ClientCAFile != "" {
		pem, err := os.ReadFile(o.ClientCAFile)
		if err != nil {
			return nil, "", fmt.Errorf("serve: read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, "", fmt.Errorf("serve: no certificate found in client CA %q", o.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		mode = modeMTLS
	}

	return credentials.NewTLS(cfg), mode, nil
}
