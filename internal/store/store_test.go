package store

import (
	"path/filepath"
	"testing"
	"time"

	"sni-scanner/internal/geo"
	"sni-scanner/internal/probe"
)

func TestSaveListLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	id := NewRunID(time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC))
	meta := RunMeta{
		RunID:          id,
		StartedAt:      time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
		Flags:          map[string]string{"limit": "10"},
		Geo:            geo.Result{Country: "IR", ASN: "AS12345", OK: true},
		CandidateCount: 2,
		PassedCount:    1,
	}
	records := []probe.Record{
		{Domain: "a.tld", Pass: true, HandshakeMS: 11.5},
		{Domain: "b.tld", Pass: false, HandshakeMS: 90},
	}
	if err := st.Save(meta, records); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Simulate a full process restart: brand new Store value, same directory.
	st2 := New(dir)
	runs, err := st2.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(runs) != 1 || runs[0].RunID != id || runs[0].PassedCount != 1 {
		t.Fatalf("unexpected list result: %+v", runs)
	}
	if runs[0].Geo.ASN != "AS12345" {
		t.Fatalf("geo metadata lost: %+v", runs[0].Geo)
	}

	gotMeta, gotRecords, err := st2.Load(id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if gotMeta.CandidateCount != 2 || len(gotRecords) != 2 {
		t.Fatalf("unexpected load result: %+v / %d records", gotMeta, len(gotRecords))
	}
	if gotRecords[0].Domain != "a.tld" || !gotRecords[0].Pass {
		t.Fatalf("record data lost: %+v", gotRecords[0])
	}
}

func TestInvalidAndMissingRunID(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)
	for _, bad := range []string{"", "..", "../etc", `a\b`, "x/y"} {
		if _, _, err := st.Load(bad); err == nil {
			t.Fatalf("expected error for run id %q", bad)
		}
	}
	if _, _, err := st.Load("does-not-exist"); err == nil {
		t.Fatal("expected error for missing run")
	}
}

func TestListEmptyDir(t *testing.T) {
	runs, err := New(filepath.Join(t.TempDir(), "nope")).List()
	if err != nil {
		t.Fatalf("missing store dir should not error: %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("expected no runs, got %d", len(runs))
	}
}
