// Package store persists scan runs so results survive a restart and can be
// listed or exported later.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sni-scanner/internal/geo"
	"sni-scanner/internal/probe"
)

// RunMeta is the metadata persisted next to a run's records.
type RunMeta struct {
	RunID          string            `json:"run_id"`
	StartedAt      time.Time         `json:"started_at"`
	Flags          map[string]string `json:"flags"`
	Geo            geo.Result        `json:"geo"`
	CandidateCount int               `json:"candidate_count"`
	PassedCount    int               `json:"passed_count"`
	Note           string            `json:"note,omitempty"`
}

// Store persists runs under Dir.
type Store struct{ Dir string }

// New returns a store rooted at dir (defaults to "runs").
func New(dir string) *Store {
	if strings.TrimSpace(dir) == "" {
		dir = "runs"
	}
	return &Store{Dir: dir}
}

// NewRunID builds a sortable, unique run identifier.
func NewRunID(t time.Time) string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return t.UTC().Format("20060102-150405")
	}
	return t.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// Save writes run.json and results.json for a run.
func (s *Store) Save(meta RunMeta, records []probe.Record) error {
	dir := filepath.Join(s.Dir, meta.RunID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create run directory: %v", err)
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if records == nil {
		records = []probe.Record{}
	}
	recBytes, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "run.json"), metaBytes); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "results.json"), recBytes)
}

// List returns run metadata, newest first.
func (s *Store) List() ([]RunMeta, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read store directory: %v", err)
	}
	var out []RunMeta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.Dir, e.Name(), "run.json"))
		if err != nil {
			continue
		}
		var m RunMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		if m.RunID == "" {
			m.RunID = e.Name()
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// Load returns a stored run.
func (s *Store) Load(runID string) (RunMeta, []probe.Record, error) {
	if err := validateRunID(runID); err != nil {
		return RunMeta{}, nil, err
	}
	dir := filepath.Join(s.Dir, runID)
	metaRaw, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		return RunMeta{}, nil, fmt.Errorf("run %q not found in %s", runID, s.Dir)
	}
	var meta RunMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return RunMeta{}, nil, fmt.Errorf("corrupt run.json for %q: %v", runID, err)
	}
	recRaw, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		return RunMeta{}, nil, fmt.Errorf("run %q has no results.json: %v", runID, err)
	}
	var records []probe.Record
	if err := json.Unmarshal(recRaw, &records); err != nil {
		return RunMeta{}, nil, fmt.Errorf("corrupt results.json for %q: %v", runID, err)
	}
	return meta, records, nil
}

func validateRunID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("empty run id")
	}
	if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return fmt.Errorf("invalid run id %q", id)
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
