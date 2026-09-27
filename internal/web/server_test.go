package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sni-scanner/internal/geo"
	"sni-scanner/internal/probe"
	"sni-scanner/internal/store"
)

func seed(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st := store.New(dir)
	id := store.NewRunID(time.Now())
	meta := store.RunMeta{
		RunID:          id,
		StartedAt:      time.Now().UTC(),
		Geo:            geo.Result{Country: "IR", ASN: "AS12345", OK: true, Source: "ip-api.com"},
		CandidateCount: 2,
		PassedCount:    1,
		Note:           "dashboard test run",
	}
	records := []probe.Record{
		{
			Domain: "good.tld", IP: "203.0.113.10", TLSVersion: "TLS 1.3", ALPN: "h2",
			HandshakeMS: 12.4, HTTPStatus: 200, ServerHeader: "nginx", Pass: true, CertIssuer: "Demo CA",
			Verdicts: []probe.Verdict{{Gate: probe.GateTLS, Pass: true}},
		},
		{
			Domain: "bad.tld", IP: "203.0.113.11", TLSVersion: "TLS 1.2", ALPN: "http/1.1",
			HandshakeMS: 91.0, HTTPStatus: 403, ServerHeader: "cloudflare",
			Verdicts: []probe.Verdict{{Gate: probe.GateTLS, Pass: false, Reason: "tls_version"}},
		},
	}
	if err := st.Save(meta, records); err != nil {
		t.Fatal(err)
	}
	return st, id
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, b.String()
}

func TestDashboardIndexAndDetail(t *testing.T) {
	st, id := seed(t)
	srv := httptest.NewServer(Handler(st))
	defer srv.Close()

	resp, body := get(t, srv.URL+"/")
	if resp.StatusCode != 200 {
		t.Fatalf("index status %d", resp.StatusCode)
	}
	if !strings.Contains(body, id) {
		t.Fatalf("index does not list run id %s", id)
	}
	if !strings.Contains(body, "read-only") {
		t.Fatal("index should state the read-only contract")
	}

	resp, body = get(t, srv.URL+"/run/"+id)
	if resp.StatusCode != 200 {
		t.Fatalf("detail status %d", resp.StatusCode)
	}
	for _, want := range []string{"good.tld", "bad.tld", "TLS 1.3", "G1:tls_version", "Disqualified"} {
		if !strings.Contains(body, want) {
			t.Fatalf("detail page missing %q", want)
		}
	}
}

func TestDashboardAPIAndMissingRun(t *testing.T) {
	st, id := seed(t)
	srv := httptest.NewServer(Handler(st))
	defer srv.Close()

	resp, body := get(t, srv.URL+"/api/runs")
	if resp.StatusCode != 200 || !strings.Contains(body, id) {
		t.Fatalf("api/runs returned %d: %s", resp.StatusCode, body)
	}
	resp, body = get(t, srv.URL+"/api/run/"+id)
	if resp.StatusCode != 200 || !strings.Contains(body, "good.tld") {
		t.Fatalf("api/run returned %d: %s", resp.StatusCode, body)
	}
	resp, _ = get(t, srv.URL+"/run/nope")
	if resp.StatusCode != 404 {
		t.Fatalf("missing run should be 404, got %d", resp.StatusCode)
	}
}
