package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"sni-scanner/internal/candidates"
	"sni-scanner/internal/fixture"
)

func TestClassifyHTTP(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		server   string
		location string
		body     string
		want     string
	}{
		{"ok", 200, "nginx", "", "<html>fine</html>", ""},
		{"same-site redirect", 301, "nginx", "https://example.tld/home", "", ""},
		{"relative redirect", 302, "nginx", "/login", "", ""},
		{"cross-site redirect", 301, "nginx", "https://evil.example/", "", "http_redirect_cross_site"},
		{"redirect without location", 302, "nginx", "", "", "http_redirect"},
		{"not found", 404, "nginx", "", "", "http_status"},
		{"challenge body", 403, "cloudflare", "", "Just a moment... challenge-platform", "challenge"},
		{"cloudflare status", 503, "cloudflare", "", "", "challenge"},
		{"login form", 200, "nginx", "", `<form><input type="password" name="p"></form>`, "login"},
		{"datadome", 200, "nginx", "", "px-captcha", "challenge"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, _ := classifyHTTP(tc.status, tc.server, tc.location, []byte(tc.body), "example.tld")
			if reason != tc.want {
				t.Fatalf("got %q, want %q", reason, tc.want)
			}
		})
	}
}

func reasonFor(rec Record, gate string) string {
	for _, v := range rec.Verdicts {
		if v.Gate == gate {
			return v.Reason
		}
	}
	return ""
}

func poolFromPEM(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(blob) {
		t.Fatal("no certificates in PEM")
	}
	return pool
}

// TestPipelineAgainstFixtures runs the full G1..G5 pipeline against the bundled
// local TLS fixtures: no network access required.
func TestPipelineAgainstFixtures(t *testing.T) {
	env, err := fixture.Start(t.TempDir())
	if err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer env.Close()

	cands, err := candidates.LoadFile(env.ListFile)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if len(cands) != len(env.Servers) {
		t.Fatalf("expected %d candidates, got %d", len(env.Servers), len(cands))
	}

	expected := map[string]fixture.Server{}
	for _, s := range env.Servers {
		expected[s.Domain] = s
	}

	opts := Options{Timeout: 5 * time.Second, Samples: 2, MaxRTTms: 5000, ExtraRoots: poolFromPEM(t, env.CAFile), PerHost: 2}
	for _, c := range cands {
		rec := Run(context.Background(), c, opts)
		exp := expected[c.Domain]
		if rec.Pass != exp.ExpectPass {
			t.Errorf("%s: pass=%v want %v (verdicts %+v)", c.Domain, rec.Pass, exp.ExpectPass, rec.Verdicts)
		}
		if !exp.ExpectPass {
			if got := reasonFor(rec, exp.ExpectGate); got != exp.ExpectReason {
				t.Errorf("%s: gate %s reason=%q want %q", c.Domain, exp.ExpectGate, got, exp.ExpectReason)
			}
		}
		if rec.IP == "" {
			t.Errorf("%s: expected a resolved IP", c.Domain)
		}
		t.Logf("%-28s pass=%-5v tls=%-8s alpn=%-5s rtt=%6.1fms http=%d",
			rec.Domain, rec.Pass, rec.TLSVersion, rec.ALPN, rec.HandshakeMS, rec.HTTPStatus)
	}
}

// TestSelfSignedFailsG3 covers the certificate gate with a self-signed leaf.
func TestSelfSignedFailsG3(t *testing.T) {
	domain, addr := startSelfSigned(t)
	rec := Run(context.Background(), candidates.Candidate{Domain: domain, ConnectAddr: addr},
		Options{Timeout: 5 * time.Second, Samples: 1, MaxRTTms: 5000})
	if rec.Pass {
		t.Fatal("self-signed certificate must not pass")
	}
	if got := reasonFor(rec, GateCert); got != "cert_selfsigned" {
		t.Fatalf("expected cert_selfsigned, got %q (verdicts %+v)", got, rec.Verdicts)
	}
}

// TestDNSFailureFailsAllGates keeps the failure path human-readable.
func TestDNSFailureFailsAllGates(t *testing.T) {
	rec := Run(context.Background(), candidates.Candidate{
		Domain:      "no-such-host.invalid",
		ConnectAddr: "no-such-host.invalid:443",
	}, Options{Timeout: time.Second, Samples: 1, MaxRTTms: 1000})
	if rec.Pass {
		t.Fatal("unresolvable host must fail")
	}
	if len(rec.Verdicts) != len(AllGates) {
		t.Fatalf("expected a verdict for every gate, got %d", len(rec.Verdicts))
	}
	if rec.Verdicts[0].Reason != "dns" {
		t.Fatalf("expected dns reason, got %q", rec.Verdicts[0].Reason)
	}
}

func startSelfSigned(t *testing.T) (string, string) {
	t.Helper()
	const domain = "self-signed-demo.tld"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{domain},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	return domain, ln.Addr().String()
}
