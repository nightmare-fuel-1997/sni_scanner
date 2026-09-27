package candidates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeList(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileForms(t *testing.T) {
	p := writeList(t, `# comment
example.tld
5,ranked.example.tld
addr.example.tld,127.0.0.1:8443
7,full.example.tld,127.0.0.1:9443
`)
	cands, err := LoadFile(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cands) != 4 {
		t.Fatalf("expected 4 candidates, got %d", len(cands))
	}
	if cands[0].Domain != "example.tld" || cands[0].ConnectAddr != "example.tld:443" {
		t.Fatalf("plain form parsed wrong: %+v", cands[0])
	}
	if cands[1].Rank != 5 || cands[1].Domain != "ranked.example.tld" {
		t.Fatalf("rank form parsed wrong: %+v", cands[1])
	}
	if cands[2].Domain != "addr.example.tld" || cands[2].ConnectAddr != "127.0.0.1:8443" {
		t.Fatalf("addr form parsed wrong: %+v", cands[2])
	}
	if cands[3].Rank != 7 || cands[3].ConnectAddr != "127.0.0.1:9443" {
		t.Fatalf("full form parsed wrong: %+v", cands[3])
	}
}

func TestLoadFileErrors(t *testing.T) {
	cases := map[string]string{
		"empty file":      "# only a comment\n",
		"bad domain":      "not a domain\n",
		"missing dot":     "localhost\n",
		"bad rank":        "abc,example.tld\n",
		"too many fields": "1,a.tld,b.tld,c.tld\n",
		"bad port":        "a.tld,127.0.0.1:99999\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFile(writeList(t, body)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFilterCountry(t *testing.T) {
	in := []Candidate{
		{Domain: "shop.example.ir"},
		{Domain: "news.example.com"},
		{Domain: "EXAMPLE.IR"},
	}
	kept, removed := FilterCountry(in, "ir")
	if len(kept) != 2 || removed != 1 {
		t.Fatalf("expected 2 kept / 1 removed, got %d/%d", len(kept), removed)
	}
	if kept, removed := FilterCountry(in, ""); len(kept) != 3 || removed != 0 {
		t.Fatal("empty country code should keep everything")
	}
}

func TestSameASN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"asn":["AS12345"],"prefix":"1.2.3.0/24"}}`))
	}))
	defer srv.Close()

	f := NewASNFilter()
	f.BaseURL = srv.URL
	f.Interval = 0
	f.Now = func() time.Time { return time.Unix(0, 0) }

	same, err := f.SameASN(context.Background(), "AS12345", "1.2.3.4")
	if err != nil || !same {
		t.Fatalf("expected same ASN: %v %v", same, err)
	}
	same, err = f.SameASN(context.Background(), "AS999", "1.2.3.4")
	if err != nil || same {
		t.Fatalf("expected different ASN: %v %v", same, err)
	}
}

func TestFilterByASNRequiresASN(t *testing.T) {
	if _, _, err := FilterByASN(context.Background(), NewASNFilter(), nil, ""); err == nil {
		t.Fatal("expected error when ASN is empty")
	}
}
