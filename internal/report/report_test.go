package report

import (
	"encoding/json"
	"strings"
	"testing"

	"sni-scanner/internal/probe"
)

func sample() []probe.Record {
	return []probe.Record{
		{
			Domain: "good.tld", IP: "203.0.113.10", TLSVersion: "TLS 1.3", ALPN: "h2",
			HandshakeMS: 12.4, HTTPStatus: 200, ServerHeader: "nginx", Pass: true,
			Verdicts: []probe.Verdict{{Gate: probe.GateTLS, Pass: true}},
		},
		{
			Domain: "bad.tld", IP: "203.0.113.11", TLSVersion: "TLS 1.2", ALPN: "http/1.1",
			HandshakeMS: 88.0, HTTPStatus: 403, ServerHeader: "cloudflare", Pass: false,
			Verdicts: []probe.Verdict{{Gate: probe.GateTLS, Pass: false, Reason: "tls_version"}},
		},
	}
}

func TestTableRendersSpecColumns(t *testing.T) {
	out := Table(sample(), 0)
	for _, col := range Header {
		if !strings.Contains(out, col) {
			t.Fatalf("table missing column %q", col)
		}
	}
	if !strings.Contains(out, "good.tld") || !strings.Contains(out, "12.4 ms") {
		t.Fatalf("table missing row data:\n%s", out)
	}
	if lines := strings.Count(out, "\n"); lines != 4 {
		t.Fatalf("expected header + rule + 2 rows, got %d lines", lines)
	}
}

func TestTableLimit(t *testing.T) {
	out := Table(sample(), 1)
	if strings.Contains(out, "bad.tld") {
		t.Fatal("limit 1 should drop the second row")
	}
}

func TestJSONIncludesVerdicts(t *testing.T) {
	blob, err := JSON(sample(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var doc JSONDoc
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Count != 1 || len(doc.Records) != 1 {
		t.Fatalf("unexpected count: %+v", doc)
	}
}

func TestXrayEmitsOnlyPassing(t *testing.T) {
	out := Xray(sample(), 0)
	if !strings.Contains(out, `"dest": "good.tld:443"`) {
		t.Fatalf("missing dest: %s", out)
	}
	if !strings.Contains(out, `"www.good.tld"`) {
		t.Fatalf("missing www serverName: %s", out)
	}
	if strings.Contains(out, "bad.tld") {
		t.Fatal("xray snippet must only include passing candidates")
	}
}

func TestXrayEmpty(t *testing.T) {
	out := Xray([]probe.Record{{Domain: "x.tld"}}, 0)
	if !strings.Contains(out, "no candidate passed") {
		t.Fatalf("expected empty-state comment, got %q", out)
	}
}
