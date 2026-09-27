// Package candidates loads, filters and (opt-in) ASN-restricts the candidate
// destination domains that feed the validation pipeline.
package candidates

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Candidate is one domain to probe.
type Candidate struct {
	Rank        int    `json:"rank"`
	Domain      string `json:"domain"`
	ConnectAddr string `json:"connect_addr"`
}

// LoadFile parses a candidate list. Accepted per line:
//
//	domain
//	domain,host:port
//	rank,domain
//	rank,domain,host:port
//
// Blank lines and '#' comments (full-line or trailing) are ignored.
func LoadFile(path string) ([]Candidate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open candidate list: %v", err)
	}
	defer f.Close()

	var out []Candidate
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		var c Candidate
		switch len(parts) {
		case 1:
			c.Domain = parts[0]
		case 2:
			if n, err := strconv.Atoi(parts[0]); err == nil {
				c.Rank, c.Domain = n, parts[1]
			} else {
				c.Domain, c.ConnectAddr = parts[0], parts[1]
			}
		case 3:
			n, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: invalid rank %q", path, lineNo, parts[0])
			}
			c.Rank, c.Domain, c.ConnectAddr = n, parts[1], parts[2]
		default:
			return nil, fmt.Errorf("%s:%d: too many comma-separated fields", path, lineNo)
		}
		if err := validateDomain(c.Domain); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, lineNo, err)
		}
		if c.ConnectAddr == "" {
			c.ConnectAddr = net.JoinHostPort(c.Domain, "443")
		} else {
			h, p, err := net.SplitHostPort(c.ConnectAddr)
			if err != nil || h == "" {
				return nil, fmt.Errorf("%s:%d: invalid host:port %q", path, lineNo, c.ConnectAddr)
			}
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("%s:%d: invalid port in %q", path, lineNo, c.ConnectAddr)
			}
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read candidate list: %v", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no candidate domains found", path)
	}
	return out, nil
}

func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("empty domain")
	}
	if strings.ContainsAny(d, " \t/\\:@") {
		return fmt.Errorf("invalid domain %q", d)
	}
	if !strings.Contains(d, ".") {
		return fmt.Errorf("invalid domain %q: expected a dotted name", d)
	}
	return nil
}

// FilterCountry keeps candidates whose registrable suffix matches the country
// code (ccTLD match), which is the plan's baseline definition of a "native"
// domain. It returns the kept list and the number of removed entries.
func FilterCountry(cands []Candidate, countryCode string) ([]Candidate, int) {
	cc := strings.ToLower(strings.TrimSpace(countryCode))
	if cc == "" {
		return cands, 0
	}
	suffix := "." + cc
	kept := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if strings.HasSuffix(strings.ToLower(c.Domain), suffix) {
			kept = append(kept, c)
		}
	}
	return kept, len(cands) - len(kept)
}

// ASNFilter queries RIPE Stat for the announcing ASN of an IP address.
// It is rate limited and only used when --asn-only is passed (opt-in).
type ASNFilter struct {
	BaseURL    string
	Interval   time.Duration
	HTTPClient *http.Client
	Now        func() time.Time

	mu   sync.Mutex
	last time.Time
}

// DefaultASNURL is the RIPE Stat network-info endpoint.
const DefaultASNURL = "https://stat.ripe.net/data/network-info/data.json"

// NewASNFilter returns a rate-limited RIPE Stat client.
func NewASNFilter() *ASNFilter {
	return &ASNFilter{
		BaseURL:    DefaultASNURL,
		Interval:   time.Second,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		Now:        time.Now,
	}
}

type networkInfo struct {
	Data struct {
		ASN    []string `json:"asn"`
		Prefix string   `json:"prefix"`
	} `json:"data"`
}

// SameASN reports whether ip is announced by asn.
// Transient network errors and rate-limit/server errors (429/5xx) are retried
// up to 3 times so a single slow RIPE response does not abort the whole scan.
func (f *ASNFilter) SameASN(ctx context.Context, asn, ip string) (bool, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
		if err := f.wait(ctx); err != nil {
			return false, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.BaseURL+"?resource="+url.QueryEscape(ip), nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("User-Agent", "sni-scanner/1.0 (asn filter)")
		resp, err := f.HTTPClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("ripe stat returned status %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return false, fmt.Errorf("ripe stat returned status %d", resp.StatusCode)
		}
		var info networkInfo
		err = json.NewDecoder(resp.Body).Decode(&info)
		resp.Body.Close()
		if err != nil {
			return false, err
		}
		want := strings.TrimSpace(asn)
		for _, a := range info.Data.ASN {
			if strings.EqualFold(strings.TrimSpace(a), want) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, lastErr
}

func (f *ASNFilter) wait(ctx context.Context) error {
	f.mu.Lock()
	now := f.Now()
	if !f.last.IsZero() {
		if d := f.Interval - now.Sub(f.last); d > 0 {
			f.mu.Unlock()
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return ctx.Err()
			}
			f.mu.Lock()
		}
	}
	f.last = f.Now()
	f.mu.Unlock()
	return nil
}

// MaxASNFilterCandidates bounds how many candidates the opt-in ASN filter will
// resolve, keeping the API usage modest.
const MaxASNFilterCandidates = 100

// FilterByASN keeps candidates whose resolved IP is announced by asn.
// It is deliberately capped and never performs port scanning of neighbours.
// A single transient RIPE/DNS failure skips that candidate instead of aborting
// the whole scan; only a total outage (every lookup failed) returns an error.
func FilterByASN(ctx context.Context, f *ASNFilter, cands []Candidate, asn string) ([]Candidate, int, error) {
	if asn == "" {
		return nil, 0, fmt.Errorf("--asn-only requires a detected ASN; geo lookup failed")
	}
	limit := len(cands)
	if limit > MaxASNFilterCandidates {
		limit = MaxASNFilterCandidates
	}
	var kept []Candidate
	skipped := 0
	consecutive := 0
	var lastErr error
	for _, c := range cands[:limit] {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		host, _, err := net.SplitHostPort(c.ConnectAddr)
		if err != nil {
			host = c.Domain
		}
		ip := host
		if net.ParseIP(host) == nil {
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil || len(ips) == 0 {
				skipped++
				consecutive++
				if len(kept) == 0 && consecutive >= 5 && limit > 5 {
					break
				}
				continue
			}
			ip = ips[0]
		}
		same, err := f.SameASN(ctx, asn, ip)
		if err != nil {
			skipped++
			consecutive++
			lastErr = err
			if len(kept) == 0 && consecutive >= 5 && limit > 5 {
				break
			}
			continue
		}
		consecutive = 0
		if same {
			kept = append(kept, c)
		}
	}
	if len(kept) == 0 && skipped == limit && limit > 0 {
		return nil, 0, fmt.Errorf("ASN lookup failed for all %d candidate(s) (last: %v) — RIPE Stat %s unreachable or timed out; retry without --asn-only or check egress to stat.ripe.net (slow links may need --timeout 20s)", limit, lastErr, f.BaseURL)
	}
	if len(kept) == 0 && skipped > 0 && len(kept)+skipped >= 5 && limit > 5 {
		// Fast-fail path: provider looks down (5+ consecutive failures, no
		// success yet) — don't burn through all 100 candidates.
		return nil, 0, fmt.Errorf("ASN lookup failed for %d candidate(s) in a row (last: %v) — RIPE Stat %s unreachable or timed out; retry without --asn-only or check egress to stat.ripe.net (slow links may need --timeout 20s)", skipped, lastErr, f.BaseURL)
	}
	return kept, len(cands) - len(kept), nil
}
