// Package geo identifies the host's public IP, city, country and ASN using
// lightweight providers with a fallback chain and a small on-disk cache.
package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Result is the detected (or overridden) network position of the host.
type Result struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Country string `json:"country"`
	ASN     string `json:"asn"`
	ASNOrg  string `json:"asn_org"`
	Source  string `json:"source"`
	OK      bool   `json:"ok"`
}

// Provider endpoints (overridable in tests).
const (
	DefaultIPAPIURL  = "http://ip-api.com/json/?fields=status,message,country,countryCode,city,query,as,asname"
	DefaultIPInfoURL = "https://ipinfo.io/json"
)

// Lookup performs geo/ASN detection.
type Lookup struct {
	HTTPClient *http.Client
	CacheFile  string
	CacheTTL   time.Duration
	IPAPIURL   string
	IPInfoURL  string
}

// New returns a Lookup caching results in cacheFile.
func New(cacheFile string) *Lookup {
	return &Lookup{
		HTTPClient: &http.Client{Timeout: 4 * time.Second},
		CacheFile:  cacheFile,
		CacheTTL:   time.Hour,
		IPAPIURL:   DefaultIPAPIURL,
		IPInfoURL:  DefaultIPInfoURL,
	}
}

type cacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	Result    Result    `json:"result"`
}

// Detect returns the best available result. It never returns an error: when
// every provider fails it returns a Result with OK=false and Source="unavailable".
func (l *Lookup) Detect(ctx context.Context) Result {
	if r, ok := l.fromCache(); ok {
		return r
	}
	if r, err := l.fromIPAPI(ctx); err == nil {
		l.toCache(r)
		return r
	}
	if r, err := l.fromIPInfo(ctx); err == nil {
		l.toCache(r)
		return r
	}
	return Result{Source: "unavailable"}
}

func (l *Lookup) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sni-scanner/1.0 (geo lookup)")
	resp, err := l.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider %s returned status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

type ipapiResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	AS          string `json:"as"`
	ASName      string `json:"asname"`
}

func (l *Lookup) fromIPAPI(ctx context.Context) (Result, error) {
	body, err := l.get(ctx, l.IPAPIURL)
	if err != nil {
		return Result{}, err
	}
	var r ipapiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return Result{}, err
	}
	if r.Status != "success" {
		return Result{}, fmt.Errorf("ip-api status %q: %s", r.Status, r.Message)
	}
	asn, org := parseASN(r.AS)
	return Result{
		IP:      r.Query,
		City:    r.City,
		Country: strings.ToUpper(r.CountryCode),
		ASN:     asn,
		ASNOrg:  firstNonEmpty(org, r.ASName),
		Source:  "ip-api.com",
		OK:      true,
	}, nil
}

type ipinfoResponse struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

func (l *Lookup) fromIPInfo(ctx context.Context) (Result, error) {
	body, err := l.get(ctx, l.IPInfoURL)
	if err != nil {
		return Result{}, err
	}
	var r ipinfoResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return Result{}, err
	}
	if r.IP == "" {
		return Result{}, fmt.Errorf("ipinfo returned no ip")
	}
	asn, org := parseASN(r.Org)
	return Result{
		IP:      r.IP,
		City:    r.City,
		Country: strings.ToUpper(r.Country),
		ASN:     asn,
		ASNOrg:  org,
		Source:  "ipinfo.io",
		OK:      true,
	}, nil
}

func (l *Lookup) fromCache() (Result, bool) {
	if l.CacheFile == "" {
		return Result{}, false
	}
	raw, err := os.ReadFile(l.CacheFile)
	if err != nil {
		return Result{}, false
	}
	var e cacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return Result{}, false
	}
	if e.Result.IP == "" || time.Since(e.FetchedAt) > l.CacheTTL {
		return Result{}, false
	}
	e.Result.Source = e.Result.Source + " (cached)"
	return e.Result, true
}

func (l *Lookup) toCache(r Result) {
	if l.CacheFile == "" {
		return
	}
	if dir := filepath.Dir(l.CacheFile); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	raw, err := json.MarshalIndent(cacheEntry{FetchedAt: time.Now().UTC(), Result: r}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(l.CacheFile, raw, 0o644)
}

// parseASN splits an "AS15169 Google LLC" style organisation string.
func parseASN(s string) (string, string) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", ""
	}
	asn := fields[0]
	if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
		return "", s
	}
	asn = "AS" + strings.TrimLeft(asn[2:], "0")
	if asn == "AS" {
		return "", s
	}
	return asn, strings.Join(fields[1:], " ")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
