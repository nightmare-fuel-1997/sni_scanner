// Package probe implements the five-gate REALITY validation pipeline (G1..G5).
package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"sni-scanner/internal/candidates"
)

// Gate identifiers.
const (
	GateTLS     = "G1" // TLS 1.3 + X25519
	GateALPN    = "G2" // ALPN h2 + http/1.1
	GateCert    = "G3" // public CA chain, unexpired, not self-signed
	GateHTTP    = "G4" // 200 / same-site 301-302, no challenge or login page
	GateLatency = "G5" // handshake RTT + jitter
)

// AllGates lists the gates in report order.
var AllGates = []string{GateTLS, GateALPN, GateCert, GateHTTP, GateLatency}

// Verdict is the outcome of a single gate for a single candidate.
type Verdict struct {
	Gate   string `json:"gate"`
	Pass   bool   `json:"pass"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Record is the full result for one candidate.
type Record struct {
	Domain       string    `json:"domain"`
	ConnectAddr  string    `json:"connect_addr"`
	IP           string    `json:"ip"`
	TLSVersion   string    `json:"tls_version"`
	KeyShare     string    `json:"key_share"`
	ALPN         string    `json:"alpn"`
	ALPNHTTP11   string    `json:"alpn_http11"`
	CertIssuer   string    `json:"cert_issuer"`
	CertNotAfter string    `json:"cert_not_after,omitempty"`
	CertChainLen int       `json:"cert_chain_len"`
	CertSANs     []string  `json:"cert_sans,omitempty"`
	HTTPStatus   int       `json:"http_status"`
	HTTPLocation string    `json:"http_location,omitempty"`
	ServerHeader string    `json:"server_header,omitempty"`
	DNSMS        float64   `json:"dns_ms"`
	TCPMS        float64   `json:"tcp_connect_ms"`
	HandshakeMS  float64   `json:"handshake_rtt_ms"`
	JitterMS     float64   `json:"jitter_ms"`
	Samples      int       `json:"samples"`
	Pass         bool      `json:"pass"`
	Verdicts     []Verdict `json:"verdicts"`
	Error        string    `json:"error,omitempty"`
}

// Options configures probing.
type Options struct {
	Timeout    time.Duration
	Samples    int
	MaxRTTms   int
	ExtraRoots *x509.CertPool
	PerHost    int
	Verbose    bool
}

// Run executes the full pipeline for one candidate.
func Run(ctx context.Context, c candidates.Candidate, o Options) Record {
	if o.Samples < 1 {
		o.Samples = 1
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	rec := Record{Domain: c.Domain, ConnectAddr: c.ConnectAddr}

	host, _, err := net.SplitHostPort(c.ConnectAddr)
	if err != nil {
		host = c.Domain
	}
	if net.ParseIP(host) == nil {
		t0 := time.Now()
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		rec.DNSMS = msSince(t0)
		if err != nil || len(ips) == 0 {
			rec.Error = fmt.Sprintf("dns lookup failed for %s", host)
			failAll(&rec, "dns", rec.Error)
			return rec
		}
		rec.IP = pickIP(ips)
	} else {
		rec.IP = host
	}

	verify := makeVerifier(c.Domain, o.ExtraRoots, &rec)

	var tcpTimes, tlsTimes []float64
	var state tls.ConnectionState
	haveState := false
	for i := 0; i < o.Samples; i++ {
		conn, tcpMS, hsMS, st, err := handshake(ctx, o, c.ConnectAddr, c.Domain, []string{"h2", "http/1.1"}, verify)
		if err != nil {
			rec.Error = err.Error()
			setVerdict(&rec, GateTLS, false, "handshake", err.Error())
			setVerdict(&rec, GateALPN, false, "handshake", "tls handshake failed")
			setVerdict(&rec, GateLatency, false, "handshake", "tls handshake failed")
			if !haveState {
				setVerdict(&rec, GateCert, false, "handshake", "tls handshake failed")
			}
			finalize(&rec)
			return rec
		}
		tcpTimes = append(tcpTimes, tcpMS)
		tlsTimes = append(tlsTimes, hsMS)
		if !haveState {
			state = st
			haveState = true
		}
		conn.Close()
	}

	// G1 — TLS 1.3 (curve preference is locked to X25519, so a completed
	// handshake implies an X25519 key exchange).
	rec.Samples = o.Samples
	rec.TLSVersion = tlsVersionName(state.Version)
	rec.KeyShare = "x25519"
	if state.Version == tls.VersionTLS13 {
		setVerdict(&rec, GateTLS, true, "", "negotiated "+rec.TLSVersion+" with x25519 key share")
	} else {
		setVerdict(&rec, GateTLS, false, "tls_version", "negotiated "+rec.TLSVersion+", TLS 1.3 required")
	}

	// G2 — ALPN: the h2-preferring handshake above plus a dedicated
	// http/1.1-only handshake must both be honoured.
	rec.ALPN = state.NegotiatedProtocol
	if conn, _, _, st, err := handshake(ctx, o, c.ConnectAddr, c.Domain, []string{"http/1.1"}, verify); err == nil {
		rec.ALPNHTTP11 = st.NegotiatedProtocol
		conn.Close()
	}
	switch {
	case rec.ALPN == "h2" && rec.ALPNHTTP11 == "http/1.1":
		setVerdict(&rec, GateALPN, true, "", fmt.Sprintf("negotiated h2 and http/1.1 (h2-preferring=%q, http1.1-only=%q)", rec.ALPN, rec.ALPNHTTP11))
	case rec.ALPN != "h2":
		setVerdict(&rec, GateALPN, false, "alpn_h2", fmt.Sprintf("h2 not negotiated (got %q)", rec.ALPN))
	default:
		setVerdict(&rec, GateALPN, false, "alpn_http11", fmt.Sprintf("http/1.1 not negotiated when offered alone (got %q)", rec.ALPNHTTP11))
	}

	// G5 — latency and stability.
	if len(tcpTimes) > 0 {
		rec.TCPMS = median(tcpTimes)
	}
	rec.HandshakeMS = median(tlsTimes)
	rec.JitterMS = stddev(tlsTimes)
	if rec.HandshakeMS <= float64(o.MaxRTTms) {
		setVerdict(&rec, GateLatency, true, "", fmt.Sprintf("median TLS handshake %.1f ms over %d sample(s), jitter %.2f ms, limit %d ms", rec.HandshakeMS, o.Samples, rec.JitterMS, o.MaxRTTms))
	} else {
		setVerdict(&rec, GateLatency, false, "rtt", fmt.Sprintf("median TLS handshake %.1f ms exceeds --max-rtt %d ms", rec.HandshakeMS, o.MaxRTTms))
	}

	// G4 — HTTP layer.
	status, location, server, reason, detail := checkHTTP(ctx, c, o, verify)
	rec.HTTPStatus, rec.HTTPLocation, rec.ServerHeader = status, location, server
	setVerdict(&rec, GateHTTP, reason == "", reason, detail)

	finalize(&rec)
	return rec
}

// RunAll probes every candidate with a global concurrency limit and a
// per-connect-address limit (guardrail: never hammer one host).
func RunAll(ctx context.Context, cands []candidates.Candidate, o Options, concurrency int, progress func(Record)) []Record {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]Record, len(cands))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	hl := newHostLimiter(o.PerHost)

	for i := range cands {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			release, err := hl.acquire(ctx, cands[i].ConnectAddr)
			if err != nil {
				return
			}
			defer release()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			results[i] = Run(ctx, cands[i], o)
			if progress != nil {
				progress(results[i])
			}
		}(i)
	}
	wg.Wait()
	return results
}

type hostLimiter struct {
	mu sync.Mutex
	n  int
	m  map[string]chan struct{}
}

func newHostLimiter(perHost int) *hostLimiter {
	if perHost < 1 {
		perHost = 1
	}
	return &hostLimiter{n: perHost, m: map[string]chan struct{}{}}
}

func (h *hostLimiter) acquire(ctx context.Context, host string) (func(), error) {
	h.mu.Lock()
	ch, ok := h.m[host]
	if !ok {
		ch = make(chan struct{}, h.n)
		h.m[host] = ch
	}
	h.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func handshake(ctx context.Context, o Options, addr, serverName string, alpn []string,
	verify func([][]byte, [][]*x509.Certificate) error) (*tls.Conn, float64, float64, tls.ConnectionState, error) {

	d := net.Dialer{Timeout: o.Timeout}
	tcpStart := time.Now()
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, 0, tls.ConnectionState{}, err
	}
	tcpMS := msSince(tcpStart)

	cfg := &tls.Config{
		ServerName:            serverName,
		NextProtos:            alpn,
		MinVersion:            tls.VersionTLS12,
		MaxVersion:            tls.VersionTLS13,
		CurvePreferences:      []tls.CurveID{tls.X25519},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verify,
	}
	conn := tls.Client(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	hsStart := time.Now()
	if err := conn.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, tcpMS, 0, tls.ConnectionState{}, err
	}
	return conn, tcpMS, msSince(hsStart), conn.ConnectionState(), nil
}

func makeVerifier(domain string, extra *x509.CertPool, rec *Record) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				setVerdict(rec, GateCert, false, "cert_parse", err.Error())
				return nil
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 {
			setVerdict(rec, GateCert, false, "cert_empty", "no peer certificates presented")
			return nil
		}
		leaf := certs[0]
		rec.CertIssuer = leaf.Issuer.CommonName
		if rec.CertIssuer == "" {
			rec.CertIssuer = leaf.Issuer.String()
		}
		rec.CertNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		rec.CertChainLen = len(certs)
		rec.CertSANs = leaf.DNSNames

		if len(certs) == 1 && bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
			setVerdict(rec, GateCert, false, "cert_selfsigned", "self-signed leaf certificate (issuer equals subject)")
			return nil
		}
		now := time.Now()
		if now.After(leaf.NotAfter) {
			setVerdict(rec, GateCert, false, "cert_expired", "certificate expired at "+rec.CertNotAfter)
			return nil
		}
		if now.Before(leaf.NotBefore) {
			setVerdict(rec, GateCert, false, "cert_not_yet_valid", "certificate not yet valid")
			return nil
		}
		opts := x509.VerifyOptions{
			DNSName:   domain,
			Roots:     extra,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if _, err := leaf.Verify(opts); err != nil {
			var ua x509.UnknownAuthorityError
			var ci x509.CertificateInvalidError
			var hn x509.HostnameError
			switch {
			case errors.As(err, &ua):
				setVerdict(rec, GateCert, false, "cert_untrusted", err.Error())
			case errors.As(err, &ci) && ci.Reason == x509.Expired:
				setVerdict(rec, GateCert, false, "cert_expired", err.Error())
			case errors.As(err, &hn):
				setVerdict(rec, GateCert, false, "cert_hostname", err.Error())
			default:
				setVerdict(rec, GateCert, false, "cert_chain", err.Error())
			}
			return nil
		}
		setVerdict(rec, GateCert, true, "", fmt.Sprintf("chain of %d verified against trusted roots; issuer %q", len(certs), rec.CertIssuer))
		return nil
	}
}

func setVerdict(rec *Record, gate string, pass bool, reason, detail string) {
	v := Verdict{Gate: gate, Pass: pass, Reason: reason, Detail: detail}
	for i := range rec.Verdicts {
		if rec.Verdicts[i].Gate == gate {
			rec.Verdicts[i] = v
			return
		}
	}
	rec.Verdicts = append(rec.Verdicts, v)
}

func failAll(rec *Record, reason, detail string) {
	for _, g := range AllGates {
		setVerdict(rec, g, false, reason, detail)
	}
	finalize(rec)
}

func finalize(rec *Record) {
	order := map[string]int{GateTLS: 1, GateALPN: 2, GateCert: 3, GateHTTP: 4, GateLatency: 5}
	sort.SliceStable(rec.Verdicts, func(i, j int) bool { return order[rec.Verdicts[i].Gate] < order[rec.Verdicts[j].Gate] })
	rec.Pass = len(rec.Verdicts) == len(AllGates)
	for _, v := range rec.Verdicts {
		if !v.Pass {
			rec.Pass = false
		}
	}
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	m := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[m]
	}
	return (cp[m-1] + cp[m]) / 2
}

func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	var acc float64
	for _, x := range xs {
		d := x - mean
		acc += d * d
	}
	return math.Sqrt(acc / float64(len(xs)))
}

func pickIP(ips []string) string {
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil && p.To4() != nil {
			return ip
		}
	}
	return ips[0]
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}
