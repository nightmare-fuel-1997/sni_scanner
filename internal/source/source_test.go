package source

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleCSV = `rank,domain
1,example.com
2,shop.example.ir
3,news.example.ir
4,other.example.org
5,portal.example.ir
`

func TestParseRankedCSV(t *testing.T) {
	entries, err := parseRankedCSV([]byte(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	if entries[0].Rank != 1 || entries[0].Domain != "example.com" {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}
}

func TestParseRankedCSVSkipsJunk(t *testing.T) {
	entries, _ := parseRankedCSV([]byte("header\ngarbage\n7,ok.example\n,blank\n9,second.example\n10,has space.com\n"))
	if len(entries) != 2 {
		t.Fatalf("expected 2 usable entries, got %d: %+v", len(entries), entries)
	}
}

func TestNativeSuffixes(t *testing.T) {
	if got := nativeSuffixes("ir"); len(got) != 1 || got[0] != ".ir" {
		t.Fatalf("unexpected suffixes for ir: %v", got)
	}
	if got := nativeSuffixes("US"); len(got) < 3 {
		t.Fatalf("the US should use a wider native set: %v", got)
	}
	if got := nativeSuffixes(""); got != nil {
		t.Fatalf("empty country should have no native suffixes: %v", got)
	}
}

func TestSelectHonoursNativeShare(t *testing.T) {
	entries, _ := parseRankedCSV([]byte(sampleCSV))
	sel, note := selectForCountry(entries, "ir", 4, 50) // quota = 2 native
	want := []string{"shop.example.ir", "news.example.ir", "example.com", "other.example.org"}
	if len(sel) != len(want) {
		t.Fatalf("expected %d entries, got %d: %+v", len(want), len(sel), sel)
	}
	for i, w := range want {
		if sel[i].Domain != w {
			t.Fatalf("position %d: got %s want %s (%s)", i, sel[i].Domain, w, note)
		}
	}
}

func TestSelectForCountryPrefersNative(t *testing.T) {
	entries, _ := parseRankedCSV([]byte(sampleCSV))
	sel, note := selectForCountry(entries, "ir", 4, 100)
	if len(sel) != 4 {
		t.Fatalf("expected pool of 4, got %d", len(sel))
	}
	// The three .ir entries lead; the highest-ranked global entry fills the pool.
	want := []string{"shop.example.ir", "news.example.ir", "portal.example.ir", "example.com"}
	for i, w := range want {
		if sel[i].Domain != w {
			t.Fatalf("position %d: got %s, want %s (%+v)", i, sel[i].Domain, w, sel)
		}
	}
	if !strings.HasSuffix(sel[0].Domain, ".ir") {
		t.Fatal("native domains must lead the selection")
	}
	if note == "" {
		t.Fatal("expected a descriptive note")
	}
}

func TestSelectForCountryCapsAtPool(t *testing.T) {
	entries, _ := parseRankedCSV([]byte(sampleCSV))
	sel, _ := selectForCountry(entries, "ir", 2, 100)
	if len(sel) != 2 {
		t.Fatalf("expected pool of 2, got %d", len(sel))
	}
	if sel[0].Domain != "shop.example.ir" || sel[1].Domain != "news.example.ir" {
		t.Fatalf("unexpected selection: %+v", sel)
	}
}

func TestSelectForCountryWithNoNative(t *testing.T) {
	entries, _ := parseRankedCSV([]byte("1,a.com\n2,b.net\n"))
	sel, note := selectForCountry(entries, "ir", 2, 50)
	if len(sel) != 2 {
		t.Fatalf("expected 2 global entries, got %d", len(sel))
	}
	if len(note) == 0 {
		t.Fatal("expected an explanatory note when no native entries exist")
	}
}

func TestBuildFromTrancoWithCache(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"list_id":"TESTID"}`))
	})
	mux.HandleFunc("/download/TESTID/1000000", func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(sampleCSV))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	opts := Options{
		Source:       SourceTranco,
		Country:      "IR",
		Pool:         3,
		CacheDir:     cacheDir,
		TrancoAPIURL: srv.URL + "/api/latest",
		TrancoDLBase: srv.URL + "/download",
	}

	cands, desc, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if len(cands) != 3 {
		t.Fatalf("expected 3 candidates, got %d", len(cands))
	}
	if cands[0].ConnectAddr != "shop.example.ir:443" {
		t.Fatalf("unexpected candidate: %+v", cands[0])
	}
	if hits != 1 {
		t.Fatalf("expected exactly one download, got %d", hits)
	}
	if desc == "" {
		t.Fatal("expected a description")
	}

	// Second run must be served from the cache (no extra HTTP hit).
	cands2, desc2, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("cached build failed: %v", err)
	}
	if hits != 1 {
		t.Fatalf("cache was not used: %d downloads", hits)
	}
	if len(cands2) != 3 {
		t.Fatalf("cached candidates differ: %d", len(cands2))
	}
	if desc2 == desc {
		t.Fatalf("expected the cached description to differ, both %q", desc)
	}
}

func TestBuildFromUmbrellaZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("top-1m.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(sampleCSV)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	cands, desc, err := Build(context.Background(), Options{
		Source:      SourceUmbrella,
		Country:     "ir",
		Pool:        2,
		CacheDir:    t.TempDir(),
		UmbrellaURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if len(cands) != 2 || cands[0].Domain != "shop.example.ir" {
		t.Fatalf("unexpected candidates: %+v", cands)
	}
	if desc == "" {
		t.Fatal("expected a description")
	}
}

func TestAutoFallsBackToUmbrella(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("top-1m.csv")
	_, _ = f.Write([]byte("1,ir.example.ir\n"))
	_ = zw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/latest" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	cands, desc, err := Build(context.Background(), Options{
		Source:       SourceAuto,
		Country:      "ir",
		Pool:         1,
		CacheDir:     t.TempDir(),
		TrancoAPIURL: srv.URL + "/api/latest",
		TrancoDLBase: srv.URL + "/download",
		UmbrellaURL:  srv.URL + "/umbrella.zip",
	})
	if err != nil {
		t.Fatalf("auto source should fall back: %v", err)
	}
	if len(cands) != 1 || cands[0].Domain != "ir.example.ir" {
		t.Fatalf("unexpected fallback result: %+v", cands)
	}
	if desc == "" {
		t.Fatal("expected a description")
	}
}

func TestBuildReportsAllFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()

	_, _, err := Build(context.Background(), Options{
		Source:       SourceAuto,
		TrancoAPIURL: srv.URL,
		TrancoDLBase: srv.URL,
		UmbrellaURL:  srv.URL,
		CacheDir:     t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected an error when every source fails")
	}
}

func TestBuildFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte("1,only.example.ir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cands, desc, err := Build(context.Background(), Options{Source: SourceFile, ListFile: p})
	if err != nil {
		t.Fatalf("file source failed: %v", err)
	}
	if len(cands) != 1 || desc == "" {
		t.Fatalf("unexpected result: %+v / %q", cands, desc)
	}
	if _, _, err := Build(context.Background(), Options{Source: SourceFile, ListFile: filepath.Join(t.TempDir(), "missing.txt")}); err == nil {
		t.Fatal("expected an error for a missing list file")
	}
}
