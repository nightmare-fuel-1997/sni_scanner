// Package fixture starts small local TLS servers that mirror the real-world
// cases the scanner must classify. It powers --demo and the integration tests,
// so both work with no network access.
package fixture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Server describes one fixture endpoint.
type Server struct {
	Domain       string `json:"domain"`
	Addr         string `json:"addr"`
	ExpectPass   bool   `json:"expect_pass"`
	ExpectGate   string `json:"expect_gate,omitempty"`
	ExpectReason string `json:"expect_reason,omitempty"`
	ExpectDesc   string `json:"expect_description"`
}

// Env is a running set of fixture servers plus the files that describe them.
type Env struct {
	Dir          string
	CAFile       string
	ListFile     string
	ExpectedFile string
	Servers      []Server

	servers   []*http.Server
	listeners []net.Listener
}

type spec struct {
	domain       string
	expectPass   bool
	expectGate   string
	expectReason string
	expectDesc   string
	maxTLS12     bool
	status       int
	serverHeader string
	body         string
	nextProtos   []string
}

func specs() []spec {
	return []spec{
		{
			domain:     "edge-native-demo.tld",
			expectPass: true,
			expectDesc: "clean TLS 1.3 target advertising h2 + http/1.1 and serving 200 OK",
			status:     http.StatusOK,
			body:       "<!doctype html><html><head><title>Edge Native Demo</title></head><body><h1>Welcome</h1><p>Ordinary site content.</p></body></html>",
			nextProtos: []string{"h2", "http/1.1"},
		},
		{
			domain:       "legacy-tls-demo.tld",
			expectGate:   "G1",
			expectReason: "tls_version",
			expectDesc:   "TLS 1.2-only endpoint (must fail G1)",
			maxTLS12:     true,
			status:       http.StatusOK,
			body:         "<html><body>legacy</body></html>",
			nextProtos:   []string{"http/1.1"},
		},
		{
			domain:       "shield-challenge-demo.tld",
			expectGate:   "G4",
			expectReason: "challenge",
			expectDesc:   "edge-protected endpoint returning a JS challenge (must fail G4)",
			status:       http.StatusForbidden,
			serverHeader: "cloudflare",
			body:         "<html><head><title>Just a moment...</title></head><body><div id=\"challenge-platform\">Checking your browser before accessing the site. Enable JavaScript and cookies to continue.</div></body></html>",
			nextProtos:   []string{"h2", "http/1.1"},
		},
		{
			domain:       "bank-login-demo.tld",
			expectGate:   "G4",
			expectReason: "login",
			expectDesc:   "credential login page (must fail G4)",
			status:       http.StatusOK,
			serverHeader: "nginx",
			body:         "<html><head><title>Online Banking Sign In</title></head><body><form method=\"post\" action=\"/login\"><input name=\"user\"><input type=\"password\" name=\"pass\"><button>Sign in</button></form></body></html>",
			nextProtos:   []string{"h2", "http/1.1"},
		},
	}
}

// Start generates a throwaway CA, starts one TLS server per fixture spec and
// writes candidates.txt + expected-results.json into dir (a temp dir by default).
func Start(dir string) (*Env, error) {
	if dir == "" {
		d, err := os.MkdirTemp("", "sni-fixture-")
		if err != nil {
			return nil, err
		}
		dir = d
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sni-scanner Demo/Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caFile := filepath.Join(dir, "demo-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return nil, err
	}

	env := &Env{
		Dir:          dir,
		CAFile:       caFile,
		ListFile:     filepath.Join(dir, "candidates.txt"),
		ExpectedFile: filepath.Join(dir, "expected-results.json"),
	}

	var listLines []string
	for i, sp := range specs() {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(100 + i)),
			Subject:      pkix.Name{CommonName: sp.domain},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{sp.domain},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}

		minV, maxV := uint16(tls.VersionTLS13), uint16(tls.VersionTLS13)
		if sp.maxTLS12 {
			minV, maxV = tls.VersionTLS12, tls.VersionTLS12
		}
		srv := &http.Server{
			Handler: handlerFor(sp),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
				NextProtos:   sp.nextProtos,
				MinVersion:   minV,
				MaxVersion:   maxV,
			},
			ReadHeaderTimeout: 5 * time.Second,
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			env.Close()
			return nil, err
		}
		go func() { _ = srv.ServeTLS(ln, "", "") }()

		env.servers = append(env.servers, srv)
		env.listeners = append(env.listeners, ln)
		env.Servers = append(env.Servers, Server{
			Domain:       sp.domain,
			Addr:         ln.Addr().String(),
			ExpectPass:   sp.expectPass,
			ExpectGate:   sp.expectGate,
			ExpectReason: sp.expectReason,
			ExpectDesc:   sp.expectDesc,
		})
		listLines = append(listLines, fmt.Sprintf("%d,%s,%s", i+1, sp.domain, ln.Addr().String()))
	}

	if err := os.WriteFile(env.ListFile, []byte(strings.Join(listLines, "\n")+"\n"), 0o644); err != nil {
		env.Close()
		return nil, err
	}
	expected := map[string]Server{}
	for _, s := range env.Servers {
		expected[s.Domain] = s
	}
	blob, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		env.Close()
		return nil, err
	}
	if err := os.WriteFile(env.ExpectedFile, blob, 0o644); err != nil {
		env.Close()
		return nil, err
	}
	return env, nil
}

func handlerFor(sp spec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sp.serverHeader != "" {
			w.Header().Set("Server", sp.serverHeader)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if sp.status != 0 {
			w.WriteHeader(sp.status)
		}
		_, _ = io.WriteString(w, sp.body)
	})
}

// Close shuts every fixture server down.
func (e *Env) Close() {
	for _, s := range e.servers {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = s.Shutdown(ctx)
		cancel()
	}
	for _, l := range e.listeners {
		_ = l.Close()
	}
}
