// Command sni-scanner finds and validates REALITY-ready dest/SNI targets.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"sni-scanner/internal/candidates"
	"sni-scanner/internal/config"
	"sni-scanner/internal/fixture"
	"sni-scanner/internal/geo"
	"sni-scanner/internal/probe"
	"sni-scanner/internal/rank"
	"sni-scanner/internal/report"
	"sni-scanner/internal/source"
	"sni-scanner/internal/store"
	"sni-scanner/internal/web"
)

const version = "sni-scanner 1.0.0"

func main() { os.Exit(run()) }

func run() int {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stdout, config.Usage)
			return 0
		}
		fmt.Fprintf(os.Stderr, "sni-scanner: %v\n\n%s\n", err, config.Usage)
		return 2
	}
	if cfg.Version {
		fmt.Println(version)
		return 0
	}
	switch cfg.Subcommand {
	case config.SubListRuns:
		return cmdListRuns(cfg)
	case config.SubExport:
		return cmdExport(cfg)
	case config.SubValidate:
		return cmdValidate(cfg)
	case config.SubServe:
		return cmdServe(cfg)
	}
	return cmdScan(cfg)
}

func ctxForSignal() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func cmdScan(cfg *config.Config) int {
	ctx, cancel := ctxForSignal()
	defer cancel()

	rootsPath := cfg.CAFile
	var demo *fixture.Env
	var cands []candidates.Candidate
	note := ""

	if cfg.Demo {
		env, err := fixture.Start("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "sni-scanner: could not start demo fixtures: %v\n", err)
			return 1
		}
		demo = env
		defer demo.Close()
		rootsPath = env.CAFile
		cands, err = candidates.LoadFile(env.ListFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
			return 1
		}
		note = "demo mode: probed bundled local TLS fixtures (offline)"
		fmt.Fprintln(os.Stderr, "demo mode: probing bundled local fixtures — no external network traffic")
	}

	extraRoots, err := loadRoots(rootsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
		return 1
	}

	// 1) Geo / ASN detection. This is what makes candidate sourcing automatic:
	//    the detected country drives which domains look "native" to this VPS.
	geoRes := geo.Result{Source: "skipped (demo mode)"}
	if !cfg.Demo {
		geoRes = geo.New(filepath.Join(cfg.StoreDir, "geo-cache.json")).Detect(ctx)
		if cfg.Country != "" {
			geoRes.Country = cfg.Country
			geoRes.Source = "override"
			geoRes.OK = true
		}
		if geoRes.OK {
			fmt.Fprintf(os.Stderr, "host: %s %s %s (%s)\n", geoRes.Country, geoRes.ASN, geoRes.IP, geoRes.Source)
		} else {
			fmt.Fprintln(os.Stderr, "note: geo/ASN detection unavailable; country targeting and --asn-only are limited")
		}
	}

	// 2) Candidate sourcing (automatic unless --source file).
	if !cfg.Demo {
		built, desc, err := source.Build(ctx, source.Options{
			Source:      cfg.Source,
			ListFile:    cfg.ListFile,
			Country:     geoRes.Country,
			Pool:        cfg.Pool,
			NativeShare: cfg.NativeShare,
			Refresh:     cfg.Refresh,
			CacheDir:    cfg.StoreDir,
			Logf: func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, "source: "+format+"\n", args...)
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
			return 1
		}
		cands = built
		note = joinNote(note, desc)
		fmt.Fprintf(os.Stderr, "candidates: %s — %d domain(s)\n", desc, len(cands))
	}

	// 3) A hand-supplied list is filtered to the host country; automatically
	//    sourced lists already applied the country preference themselves.
	if cfg.Source == "file" && geoRes.Country != "" {
		if kept, removed := candidates.FilterCountry(cands, geoRes.Country); removed > 0 && len(kept) > 0 {
			cands = kept
			note = joinNote(note, fmt.Sprintf("country %s filter kept %d candidates (%d removed)", geoRes.Country, len(kept), removed))
		}
	}
	if cfg.ASNOnly {
		if !geoRes.OK || geoRes.ASN == "" {
			fmt.Fprintln(os.Stderr, "sni-scanner: --asn-only requires a detected ASN; geo lookup failed")
			return 1
		}
		asnFilter := candidates.NewASNFilter()
		if cfg.Timeout > asnFilter.HTTPClient.Timeout {
			asnFilter.HTTPClient.Timeout = cfg.Timeout
		}
		filtered, removed, err := candidates.FilterByASN(ctx, asnFilter, cands, geoRes.ASN)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sni-scanner: ASN filter failed: %v\n", err)
			return 1
		}
		cands = filtered
		note = joinNote(note, fmt.Sprintf("--asn-only kept %d of %d candidates in %s (opt-in)", len(filtered), len(filtered)+removed, geoRes.ASN))
	}
	if len(cands) == 0 {
		fmt.Fprintln(os.Stderr, "sni-scanner: no candidates left to probe after filtering")
		return 1
	}

	opts := probe.Options{
		Timeout:    cfg.Timeout,
		Samples:    cfg.Samples,
		MaxRTTms:   cfg.MaxRTTms,
		ExtraRoots: extraRoots,
		PerHost:    cfg.PerHost,
		Verbose:    cfg.Verbose,
	}
	var progress func(probe.Record)
	if cfg.Verbose {
		progress = func(r probe.Record) {
			fmt.Fprintf(os.Stderr, "  %-32s ip=%-15s rtt=%8.1fms  pass=%v\n", r.Domain, r.IP, r.HandshakeMS, r.Pass)
		}
	}

	records := probe.RunAll(ctx, cands, opts, cfg.Concurrency, progress)
	rank.Sort(records)
	passed := len(rank.Passing(records))

	summary, hint := failureSummary(records)
	if summary != "" {
		fmt.Fprintf(os.Stderr, "gate failures: %s\n", summary)
		note = joinNote(note, summary)
	}
	if hint != "" {
		fmt.Fprintln(os.Stderr, hint)
		note = joinNote(note, hint)
	}

	runID := store.NewRunID(time.Now())
	st := store.New(cfg.StoreDir)
	meta := store.RunMeta{
		RunID:          runID,
		StartedAt:      time.Now().UTC(),
		Flags:          flagsOf(cfg),
		Geo:            geoRes,
		CandidateCount: len(records),
		PassedCount:    passed,
		Note:           note,
	}
	if err := st.Save(meta, records); err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: warning: could not persist run: %v\n", err)
	}

	out, err := render(cfg.Output, records, cfg.Limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
		return 1
	}
	fmt.Print(out)
	fmt.Fprintf(os.Stderr, "\nrun %s stored in %s — %d candidates probed, %d passed all gates\n",
		runID, cfg.StoreDir, len(records), passed)
	return 0
}

func cmdListRuns(cfg *config.Config) int {
	st := store.New(cfg.StoreDir)
	runs, err := st.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
		return 1
	}
	if len(runs) == 0 {
		fmt.Printf("no runs found in %s\n", cfg.StoreDir)
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN ID\tSTARTED (UTC)\tCOUNTRY\tASN\tCANDIDATES\tPASSED")
	for _, r := range runs {
		country, asn := r.Geo.Country, r.Geo.ASN
		if country == "" {
			country = "—"
		}
		if asn == "" {
			asn = "—"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\n",
			r.RunID, r.StartedAt.Format("2006-01-02 15:04:05"), country, asn, r.CandidateCount, r.PassedCount)
	}
	tw.Flush()
	return 0
}

func cmdExport(cfg *config.Config) int {
	st := store.New(cfg.StoreDir)
	meta, records, err := st.Load(cfg.RunID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
		return 1
	}
	out, err := render(cfg.Output, records, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
		return 1
	}
	fmt.Printf("run %s — started %s — %d records, %d passed\n\n",
		meta.RunID, meta.StartedAt.Format(time.RFC3339), len(records), meta.PassedCount)
	fmt.Print(out)
	return 0
}

func cmdValidate(cfg *config.Config) int {
	ctx, cancel := ctxForSignal()
	defer cancel()

	st := store.New(cfg.StoreDir)
	_, records, err := st.Load(cfg.RunID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: %v\n", err)
		return 1
	}
	var cands []candidates.Candidate
	for _, r := range records {
		if r.Pass {
			cands = append(cands, candidates.Candidate{Domain: r.Domain, ConnectAddr: r.ConnectAddr})
		}
	}
	if len(cands) == 0 {
		fmt.Printf("run %s has no passing domains; nothing to re-validate\n", cfg.RunID)
		return 0
	}
	opts := probe.Options{Timeout: 5 * time.Second, Samples: 3, MaxRTTms: 100, PerHost: 2}
	newRecords := probe.RunAll(ctx, cands, opts, 8, nil)
	rank.Sort(newRecords)
	passed := len(rank.Passing(newRecords))

	newID := store.NewRunID(time.Now())
	meta := store.RunMeta{
		RunID:          newID,
		StartedAt:      time.Now().UTC(),
		Flags:          map[string]string{"validate": cfg.RunID},
		CandidateCount: len(newRecords),
		PassedCount:    passed,
		Note:           "re-validation of run " + cfg.RunID,
	}
	if err := st.Save(meta, newRecords); err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: warning: could not persist re-validation: %v\n", err)
	}
	fmt.Printf("re-validated %d domain(s) from run %s — %d still pass (new run %s)\n\n",
		len(newRecords), cfg.RunID, passed, newID)
	fmt.Print(report.Table(newRecords, 0))
	for _, r := range newRecords {
		if r.Pass {
			continue
		}
		var reasons []string
		for _, v := range r.Verdicts {
			if !v.Pass && v.Reason != "" {
				reasons = append(reasons, v.Gate+":"+v.Reason)
			}
		}
		fmt.Printf("  %s no longer passes — %s\n", r.Domain, strings.Join(reasons, ", "))
	}
	return 0
}

func cmdServe(cfg *config.Config) int {
	addr := cfg.Addr
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:8787"
	}
	st := store.New(cfg.StoreDir)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sni-scanner: cannot listen on %s: %v\n", addr, err)
		return 1
	}
	srv := &http.Server{Handler: web.Handler(st), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Printf("sni-scanner dashboard: http://%s  (store %s)\npress Ctrl+C to stop\n", ln.Addr().String(), st.Dir)

	ctx, cancel := ctxForSignal()
	defer cancel()
	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
	return 0
}

func render(f config.OutputFormat, records []probe.Record, limit int) (string, error) {
	switch f {
	case config.OutputTable:
		return report.Table(records, limit), nil
	case config.OutputJSON:
		blob, err := report.JSON(records, limit)
		if err != nil {
			return "", err
		}
		return string(blob) + "\n", nil
	case config.OutputXray:
		return report.Xray(records, limit), nil
	}
	return "", fmt.Errorf("unsupported output format %q", string(f))
}

func loadRoots(path string) (*x509.CertPool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(blob) {
		return nil, fmt.Errorf("no usable PEM certificates in %s", path)
	}
	return pool, nil
}

func primaryReason(r probe.Record) string {
	for _, v := range r.Verdicts {
		if !v.Pass {
			if v.Reason != "" {
				return v.Reason
			}
			return "other"
		}
	}
	return "unknown"
}

func isTimeoutText(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "deadline exceeded") ||
		strings.Contains(low, "i/o timeout") ||
		strings.Contains(low, "timeout")
}

// failureSummary groups failing candidates by their first failing gate reason
// and, when timeouts dominate, suggests more conservative settings. On a slow or
// throttled egress the default concurrency can make every probe time out, which
// otherwise looks like "nothing works".
func failureSummary(records []probe.Record) (string, string) {
	counts := map[string]int{}
	timeouts, failures := 0, 0
	for _, r := range records {
		if r.Pass {
			continue
		}
		failures++
		counts[primaryReason(r)]++
		hit := isTimeoutText(r.Error)
		if !hit {
			for _, v := range r.Verdicts {
				if !v.Pass && isTimeoutText(v.Detail) {
					hit = true
					break
				}
			}
		}
		if hit {
			timeouts++
		}
	}
	if failures == 0 {
		return "", ""
	}
	top := make([]string, 0, len(counts))
	for k, v := range counts {
		top = append(top, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(top)
	summary := fmt.Sprintf("%d/%d disqualified (%s)", failures, len(records), strings.Join(top, ", "))

	if timeouts*3 >= failures && failures >= 3 {
		hint := fmt.Sprintf("hint: %d probe(s) hit timeouts — this host's egress looks slow or throttled. "+
			"Retry with --concurrency 8 --timeout 20s and raise --max-rtt to match the measured RTT.", timeouts)
		return summary, hint
	}
	return summary, ""
}

func flagsOf(cfg *config.Config) map[string]string {
	return map[string]string{
		"limit":        fmt.Sprintf("%d", cfg.Limit),
		"max_rtt_ms":   fmt.Sprintf("%d", cfg.MaxRTTms),
		"asn_only":     fmt.Sprintf("%t", cfg.ASNOnly),
		"output":       string(cfg.Output),
		"country":      cfg.Country,
		"list_file":    cfg.ListFile,
		"concurrency":  fmt.Sprintf("%d", cfg.Concurrency),
		"per_host":     fmt.Sprintf("%d", cfg.PerHost),
		"samples":      fmt.Sprintf("%d", cfg.Samples),
		"timeout":      cfg.Timeout.String(),
		"demo":         fmt.Sprintf("%t", cfg.Demo),
		"source":       cfg.Source,
		"pool":         fmt.Sprintf("%d", cfg.Pool),
		"native_share": fmt.Sprintf("%d", cfg.NativeShare),
		"refresh":      fmt.Sprintf("%t", cfg.Refresh),
	}
}

func joinNote(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + "; " + addition
}
