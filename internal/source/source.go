// Package source builds the candidate domain list automatically from the
// host's detected country, using public top-site lists with a local cache.
//
// Sources:
//   - Tranco (https://tranco-list.eu) — aggregated, manipulation-resistant ranking
//   - Cisco Umbrella top-1M — nightly popularity list
//
// The selection rule follows the plan: prefer domains that look native to the
// host's country (ccTLD match), then fill the remaining pool with the
// highest-ranked global entries so a scan always has candidates.
package source

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sni-scanner/internal/candidates"
)

// Supported source identifiers.
const (
	SourceAuto     = "auto"
	SourceTranco   = "tranco"
	SourceUmbrella = "umbrella"
	SourceFile     = "file"
)

// Default endpoints (overridable in tests).
const (
	DefaultTrancoAPIURL    = "https://tranco-list.eu/api/lists/date/latest"
	DefaultTrancoDLBase    = "https://tranco-list.eu/download"
	DefaultUmbrellaZIP     = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
	DefaultPool            = 200
	DefaultNativeShare     = 50
	MaxPool                = 5000
	MaxParsedEntries       = 300000
	DefaultCacheTTL        = 24 * time.Hour
	DefaultDownloadTimeout = 180 * time.Second
)

// Options controls candidate sourcing.
type Options struct {
	Source      string // auto | tranco | umbrella | file
	ListFile    string // used when Source == file
	Country     string // ISO-3166 alpha-2 of the host, from geo detection
	Pool        int    // max candidates to produce
	NativeShare int    // percent of the pool reserved for country-native entries (0-100)
	Refresh     bool   // ignore the on-disk cache
	CacheDir    string // where list downloads are cached
	Timeout     time.Duration
	Logf        func(format string, args ...any)

	// Test seams.
	TrancoAPIURL string
	TrancoDLBase string
	UmbrellaURL  string
	HTTPClient   *http.Client
	CacheTTL     time.Duration
}

type entry struct {
	Rank   int
	Domain string
}

// Build returns the candidate list plus a human-readable description of where
// it came from.
func Build(ctx context.Context, o Options) ([]candidates.Candidate, string, error) {
	if o.Source == SourceFile {
		cands, err := candidates.LoadFile(o.ListFile)
		if err != nil {
			return nil, "", err
		}
		return cands, "file " + o.ListFile, nil
	}

	order := []string{SourceTranco, SourceUmbrella}
	if o.Source != SourceAuto && o.Source != "" {
		order = []string{o.Source}
	}

	var problems []string
	for _, src := range order {
		var (
			entries []entry
			desc    string
			err     error
		)
		switch src {
		case SourceTranco:
			entries, desc, err = o.fetchTranco(ctx)
		case SourceUmbrella:
			entries, desc, err = o.fetchUmbrella(ctx)
		default:
			err = fmt.Errorf("unknown source %q", src)
		}
		if err != nil || len(entries) == 0 {
			if err == nil {
				err = fmt.Errorf("empty list")
			}
			problems = append(problems, fmt.Sprintf("%s: %v", src, err))
			continue
		}
		selected, note := selectForCountry(entries, o.Country, poolSize(o.Pool), o.NativeShare)
		if len(selected) == 0 {
			problems = append(problems, fmt.Sprintf("%s: no usable entries", src))
			continue
		}
		return toCandidates(selected), desc + note, nil
	}

	return nil, "", fmt.Errorf(
		"could not build a candidate list automatically (%s). "+
			"Check outbound HTTPS access, or pass --list-file with a local list",
		strings.Join(problems, "; "))
}

func poolSize(p int) int {
	if p <= 0 {
		return DefaultPool
	}
	if p > MaxPool {
		return MaxPool
	}
	return p
}

// nativeSuffixes returns the domain suffixes that count as "native" for a
// country. Most countries map to their ccTLD; the United States never adopted
// ".us" as a primary web TLD, so its real native footprint is the gTLD set and
// the ccTLD is included alongside it.
func nativeSuffixes(country string) []string {
	switch strings.ToLower(strings.TrimSpace(country)) {
	case "":
		return nil
	case "us":
		return []string{".us", ".com", ".org", ".net", ".gov", ".edu"}
	default:
		return []string{"." + strings.ToLower(strings.TrimSpace(country))}
	}
}

func matchesAnySuffix(domain string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(domain, s) {
			return true
		}
	}
	return false
}

// selectForCountry reserves a share of the pool for country-native entries and
// fills the remainder with the highest-ranked global entries, so a scan is
// never limited to a thin (or infrastructure-only) ccTLD slice.
func selectForCountry(entries []entry, country string, pool, nativeShare int) ([]entry, string) {
	cc := strings.ToLower(strings.TrimSpace(country))
	suffixes := nativeSuffixes(cc)
	if nativeShare <= 0 {
		nativeShare = DefaultNativeShare
	}
	if nativeShare > 100 {
		nativeShare = 100
	}
	nativeQuota := pool * nativeShare / 100
	if len(suffixes) == 0 {
		nativeQuota = 0
	}

	var local, global []entry
	seen := map[string]bool{}
	for _, e := range entries {
		d := strings.ToLower(strings.TrimSpace(e.Domain))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		if matchesAnySuffix(d, suffixes) && len(local) < nativeQuota {
			local = append(local, e)
			continue
		}
		global = append(global, e)
	}

	out := make([]entry, 0, pool)
	out = append(out, local...)
	for _, e := range global {
		if len(out) >= pool {
			break
		}
		out = append(out, e)
	}

	if len(suffixes) == 0 {
		return out, fmt.Sprintf(" (%d global entries, pool %d)", len(out), pool)
	}
	return out, fmt.Sprintf(" (%d native %s + %d global fill, pool %d, native share %d%%)",
		len(local), labelCountry(cc), len(out)-len(local), pool, nativeShare)
}

func labelCountry(cc string) string {
	if cc == "" {
		return "country"
	}
	return "." + cc
}

func toCandidates(entries []entry) []candidates.Candidate {
	out := make([]candidates.Candidate, 0, len(entries))
	for _, e := range entries {
		out = append(out, candidates.Candidate{
			Rank:        e.Rank,
			Domain:      e.Domain,
			ConnectAddr: net.JoinHostPort(e.Domain, "443"),
		})
	}
	return out
}

func (o Options) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	t := o.Timeout
	if t <= 0 {
		// Top-site lists are several MB; the probe timeout is far too short.
		t = DefaultDownloadTimeout
	}
	return &http.Client{Timeout: t}
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

func (o Options) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sni-scanner/1.0 (candidate sourcing)")
	resp, err := o.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned status %d", url, resp.StatusCode)
	}
	// Top-1M lists are ~25 MB; cap generously.
	return io.ReadAll(io.LimitReader(resp.Body, 80<<20))
}

// ---------------------------------------------------------------- Tranco ----

type trancoLatest struct {
	ListID string `json:"list_id"`
	ID     string `json:"id"`
}

func (o Options) fetchTranco(ctx context.Context) ([]entry, string, error) {
	cache := ""
	if o.CacheDir != "" {
		cache = filepath.Join(o.CacheDir, "tranco-top1m.csv")
	}
	if !o.Refresh && cache != "" {
		if raw, err := os.ReadFile(cache); err == nil {
			if e, err := parseRankedCSV(raw); err == nil && len(e) > 0 {
				o.logf("tranco: using cached list (%d entries)", len(e))
				return e, "Tranco list (cached)", nil
			}
		}
	}

	api := o.TrancoAPIURL
	if api == "" {
		api = DefaultTrancoAPIURL
	}
	raw, err := o.get(ctx, api)
	if err != nil {
		return nil, "", fmt.Errorf("latest-list lookup failed: %v", err)
	}
	var meta trancoLatest
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, "", fmt.Errorf("unexpected latest-list response: %v", err)
	}
	listID := meta.ListID
	if listID == "" {
		listID = meta.ID
	}
	if listID == "" {
		return nil, "", fmt.Errorf("latest-list response contained no list id")
	}

	base := o.TrancoDLBase
	if base == "" {
		base = DefaultTrancoDLBase
	}

	// Try a smaller slice first (fast, plenty deep for ccTLD matching), then the
	// full list, then the zip archive.
	var (
		body    []byte
		entries []entry
		csvErrs []string
	)
	for _, n := range []string{"250000", "1000000"} {
		raw, err := o.get(ctx, base+"/"+listID+"/"+n)
		if err != nil {
			csvErrs = append(csvErrs, fmt.Sprintf("%s entries: %v", n, err))
			continue
		}
		e, perr := parseRankedCSV(raw)
		if perr != nil || len(e) == 0 {
			csvErrs = append(csvErrs, fmt.Sprintf("%s entries: unparsable", n))
			continue
		}
		body, entries = raw, e
		break
	}

	if len(entries) == 0 {
		zbody, zerr := o.get(ctx, base+"/"+listID)
		if zerr != nil {
			return nil, "", fmt.Errorf("csv download failed (%s) and zip download failed (%v)", strings.Join(csvErrs, " | "), zerr)
		}
		csvBytes, zerr := firstZipEntry(zbody)
		if zerr != nil {
			return nil, "", zerr
		}
		e, perr := parseRankedCSV(csvBytes)
		if perr != nil || len(e) == 0 {
			return nil, "", fmt.Errorf("zip list unusable: %v", perr)
		}
		body, entries = csvBytes, e
	}

	if len(entries) == 0 {
		return nil, "", fmt.Errorf("list %s contained no usable entries", listID)
	}

	if cache != "" {
		if err := os.MkdirAll(filepath.Dir(cache), 0o755); err == nil {
			_ = os.WriteFile(cache, body, 0o644)
		}
	}
	o.logf("tranco: fetched list %s (%d entries)", listID, len(entries))
	return entries, "Tranco list " + listID, nil
}

// -------------------------------------------------------------- Umbrella ----

func (o Options) fetchUmbrella(ctx context.Context) ([]entry, string, error) {
	cache := ""
	if o.CacheDir != "" {
		cache = filepath.Join(o.CacheDir, "umbrella-top1m.csv")
	}
	if !o.Refresh && cache != "" {
		if raw, err := os.ReadFile(cache); err == nil {
			if e, err := parseRankedCSV(raw); err == nil && len(e) > 0 {
				o.logf("umbrella: using cached list (%d entries)", len(e))
				return e, "Cisco Umbrella top-1M (cached)", nil
			}
		}
	}

	url := o.UmbrellaURL
	if url == "" {
		url = DefaultUmbrellaZIP
	}
	blob, err := o.get(ctx, url)
	if err != nil {
		return nil, "", err
	}
	csvBytes, err := firstZipEntry(blob)
	if err != nil {
		return nil, "", err
	}
	entries, err := parseRankedCSV(csvBytes)
	if err != nil {
		return nil, "", err
	}
	if len(entries) == 0 {
		return nil, "", fmt.Errorf("umbrella list contained no usable entries")
	}
	if cache != "" {
		if err := os.MkdirAll(filepath.Dir(cache), 0o755); err == nil {
			_ = os.WriteFile(cache, csvBytes, 0o644)
		}
	}
	o.logf("umbrella: fetched %d entries", len(entries))
	return entries, "Cisco Umbrella top-1M", nil
}

// ------------------------------------------------------------------ util ----

func firstZipEntry(blob []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		return nil, fmt.Errorf("read zip: %v", err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s in zip: %v", f.Name, err)
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, 80<<20))
	}
	return nil, fmt.Errorf("zip contained no files")
}

// parseRankedCSV reads "rank,domain" rows (Tranco and Umbrella both use this).
func parseRankedCSV(raw []byte) ([]entry, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	r.ReuseRecord = true

	out := make([]entry, 0, 1024)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Tolerate a malformed trailing line rather than failing the run.
			break
		}
		if len(rec) < 2 {
			continue
		}
		rankRaw := strings.TrimSpace(rec[0])
		domain := strings.ToLower(strings.TrimSpace(rec[1]))
		rank, err := strconv.Atoi(rankRaw)
		if err != nil {
			continue // header row or junk
		}
		if !usableDomain(domain) {
			continue
		}
		out = append(out, entry{Rank: rank, Domain: domain})
		if len(out) >= MaxParsedEntries {
			break
		}
	}
	return out, nil
}

func usableDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	if strings.ContainsAny(d, " \t/\\:@,") {
		return false
	}
	return strings.Contains(d, ".")
}
