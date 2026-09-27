package geo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func jsonServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDetectViaIPAPI(t *testing.T) {
	srv := jsonServer(t, `{"status":"success","country":"Iran","countryCode":"IR","city":"Tehran","query":"203.0.113.5","as":"AS12345 Example Net","asname":"Example"}`, http.StatusOK)
	l := New(filepath.Join(t.TempDir(), "geo.json"))
	l.IPAPIURL = srv.URL

	r := l.Detect(context.Background())
	if !r.OK || r.Country != "IR" || r.ASN != "AS12345" || r.Source != "ip-api.com" {
		t.Fatalf("unexpected result: %+v", r)
	}
	if r.City != "Tehran" || r.IP != "203.0.113.5" {
		t.Fatalf("missing fields: %+v", r)
	}
}

func TestFallbackToIPInfo(t *testing.T) {
	bad := jsonServer(t, `{"status":"fail","message":"quota"}`, http.StatusOK)
	good := jsonServer(t, `{"ip":"198.51.100.7","city":"Berlin","country":"DE","org":"AS54321 Some ISP"}`, http.StatusOK)

	l := New(filepath.Join(t.TempDir(), "geo.json"))
	l.IPAPIURL = bad.URL
	l.IPInfoURL = good.URL

	r := l.Detect(context.Background())
	if !r.OK || r.Source != "ipinfo.io" || r.Country != "DE" || r.ASN != "AS54321" {
		t.Fatalf("fallback failed: %+v", r)
	}
}

func TestCacheIsUsed(t *testing.T) {
	srv := jsonServer(t, `{"status":"success","countryCode":"NL","query":"203.0.113.9","as":"AS64500 Cache Net"}`, http.StatusOK)
	cacheFile := filepath.Join(t.TempDir(), "geo.json")
	l := New(cacheFile)
	l.IPAPIURL = srv.URL

	first := l.Detect(context.Background())
	if !first.OK {
		t.Fatalf("first detect failed: %+v", first)
	}

	// Point at a dead endpoint: the cached value must still be served.
	l2 := New(cacheFile)
	l2.IPAPIURL = "http://127.0.0.1:1/"
	l2.IPInfoURL = "http://127.0.0.1:1/"
	second := l2.Detect(context.Background())
	if !second.OK || !strings.Contains(second.Source, "cached") {
		t.Fatalf("expected cached result, got %+v", second)
	}
	if second.Country != "NL" {
		t.Fatalf("cached country lost: %+v", second)
	}
}

func TestOfflineIsUnavailableNotFatal(t *testing.T) {
	l := New("")
	l.IPAPIURL = "http://127.0.0.1:1/"
	l.IPInfoURL = "http://127.0.0.1:1/"
	r := l.Detect(context.Background())
	if r.OK || r.Source != "unavailable" {
		t.Fatalf("expected graceful unavailable result, got %+v", r)
	}
}

func TestParseASN(t *testing.T) {
	asn, org := parseASN("AS15169 Google LLC")
	if asn != "AS15169" || org != "Google LLC" {
		t.Fatalf("unexpected parse: %q %q", asn, org)
	}
	if asn, org := parseASN("not-an-asn"); asn != "" || org != "not-an-asn" {
		t.Fatalf("unexpected parse for non-ASN input: %q %q", asn, org)
	}
}
