// Package config parses and validates the sni-scanner command line.
package config

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// OutputFormat selects the renderer for scan results.
type OutputFormat string

const (
	OutputTable OutputFormat = "table"
	OutputJSON  OutputFormat = "json"
	OutputXray  OutputFormat = "xray-snippet"
)

// Hard caps keep the scanner polite by construction (plan §3 guardrails).
const (
	MaxConcurrency = 512
	MaxPerHost     = 4
	MaxSamples     = 10
	MaxLimit       = 1000
	MaxRTTms       = 10000
)

// Subcommands.
const (
	SubScan     = ""
	SubListRuns = "list-runs"
	SubExport   = "export"
	SubValidate = "validate"
	SubServe    = "serve"
)

// Config is the validated, fully-parsed command line.
type Config struct {
	Limit       int
	MaxRTTms    int
	ASNOnly     bool
	Output      OutputFormat
	Country     string
	ListFile    string
	StoreDir    string
	Concurrency int
	PerHost     int
	Timeout     time.Duration
	Samples     int
	CAFile      string
	Demo        bool
	Verbose     bool
	Source      string
	Pool        int
	NativeShare int
	Refresh     bool

	Subcommand string // "", SubListRuns, SubExport, SubValidate, SubServe
	RunID      string // positional arg of export/validate
	Addr       string // --addr for the serve subcommand
	Version    bool
}

// Usage is the human-readable help text.
const Usage = `sni-scanner — find and validate REALITY-ready dest/SNI targets

usage:
  sni-scanner [scan flags]
  sni-scanner list-runs [--store-dir <path>]
  sni-scanner export <run-id> [--output <fmt>] [--store-dir <path>]
  sni-scanner validate <run-id> [--store-dir <path>]
  sni-scanner serve [--addr host:port] [--store-dir <path>]
  sni-scanner --version

By default the scanner builds its own candidate pool: it detects the host's
country/ASN, downloads a public top-site list (Tranco, then Cisco Umbrella),
prefers country-native (ccTLD) domains, and fills the rest of the pool with
high-ranked global entries. Use --list-file with --source file to override.

scan flags:
  --limit <n>           max domains in ranked output (default 10)
  --max-rtt <ms>        max TLS handshake RTT for gate G5 (default 100)
  --asn-only            restrict candidates to the server's own ASN (opt-in, default off)
  --output <fmt>        table | json | xray-snippet (default table)
  --country <cc>        override detected country (2-letter code)
  --list-file <path>    candidate list: CSV "rank,domain[,host:port]" or plain "domain[,host:port]" (needs --source file)
  --source <s>          candidate source: auto | tranco | umbrella | file (default auto)
  --pool <n>            max candidates to build from the source (default 200, cap 5000)
  --native-share <pct>  percent of the pool reserved for country-native domains (default 50, 1-100)
  --refresh             ignore the cached top-site list and re-download it
  --store-dir <path>    run store directory (default ./runs)
  --concurrency <n>     global probe concurrency (default 64, hard cap 512)
  --per-host <n>        concurrent probes per host (default 2, hard cap 4)
  --timeout <dur>       per-probe timeout (default 10s)
  --samples <n>         latency samples for RTT/jitter (default 3, cap 10)
  --ca-file <pem>       extra root CA certificate (PEM), e.g. for private CAs
  --demo                run 100% offline against bundled local TLS fixtures
  --verbose             per-candidate diagnostics on stderr
  --version             print version and exit

safety: the scanner performs benign capability measurement of public TLS/HTTP
endpoints only. Mass port scanning, login interaction, challenge solving and
exploitation are intentionally not implemented (see README).`

// Parse parses and validates argv (without the program name).
func Parse(args []string) (*Config, error) {
	if len(args) > 0 {
		switch args[0] {
		case SubListRuns:
			return parseListRuns(args[1:])
		case SubExport:
			return parseExport(args[1:])
		case SubValidate:
			return parseValidate(args[1:])
		case SubServe:
			return parseServe(args[1:])
		}
	}
	return parseScan(args)
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("sni-scanner", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseScan(args []string) (*Config, error) {
	fs := newFlagSet()
	c := &Config{}
	var output, country string
	fs.IntVar(&c.Limit, "limit", 10, "")
	fs.IntVar(&c.MaxRTTms, "max-rtt", 100, "")
	fs.BoolVar(&c.ASNOnly, "asn-only", false, "")
	fs.StringVar(&output, "output", string(OutputTable), "")
	fs.StringVar(&country, "country", "", "")
	fs.StringVar(&c.ListFile, "list-file", "", "")
	fs.StringVar(&c.StoreDir, "store-dir", "runs", "")
	fs.IntVar(&c.Concurrency, "concurrency", 64, "")
	fs.IntVar(&c.PerHost, "per-host", 2, "")
	fs.DurationVar(&c.Timeout, "timeout", 10*time.Second, "")
	fs.IntVar(&c.Samples, "samples", 3, "")
	fs.StringVar(&c.CAFile, "ca-file", "", "")
	fs.BoolVar(&c.Demo, "demo", false, "")
	fs.BoolVar(&c.Verbose, "verbose", false, "")
	fs.StringVar(&c.Source, "source", "auto", "")
	fs.IntVar(&c.Pool, "pool", 200, "")
	fs.IntVar(&c.NativeShare, "native-share", 50, "")
	fs.BoolVar(&c.Refresh, "refresh", false, "")
	fs.BoolVar(&c.Version, "version", false, "")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q (flags come first; see --help)", fs.Arg(0))
	}
	c.Output = OutputFormat(output)
	c.Country = strings.ToUpper(strings.TrimSpace(country))
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.Version {
		return nil
	}
	if c.Limit < 1 || c.Limit > MaxLimit {
		return fmt.Errorf("invalid --limit %d: must be 1..%d", c.Limit, MaxLimit)
	}
	if c.MaxRTTms < 1 || c.MaxRTTms > MaxRTTms {
		return fmt.Errorf("invalid --max-rtt %d: must be 1..%d (milliseconds)", c.MaxRTTms, MaxRTTms)
	}
	switch c.Output {
	case OutputTable, OutputJSON, OutputXray:
	default:
		return fmt.Errorf("invalid --output %q: must be table, json or xray-snippet", string(c.Output))
	}
	if c.Concurrency < 1 || c.Concurrency > MaxConcurrency {
		return fmt.Errorf("invalid --concurrency %d: must be 1..%d", c.Concurrency, MaxConcurrency)
	}
	if c.PerHost < 1 || c.PerHost > MaxPerHost {
		return fmt.Errorf("invalid --per-host %d: must be 1..%d", c.PerHost, MaxPerHost)
	}
	if c.Samples < 1 || c.Samples > MaxSamples {
		return fmt.Errorf("invalid --samples %d: must be 1..%d", c.Samples, MaxSamples)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("invalid --timeout %s: must be positive", c.Timeout)
	}
	if c.Country != "" {
		if len(c.Country) != 2 || !isLetters(c.Country) {
			return fmt.Errorf("invalid --country %q: must be a 2-letter country code", c.Country)
		}
	}
	if c.CAFile != "" {
		f, err := os.Open(c.CAFile)
		if err != nil {
			return fmt.Errorf("unreadable --ca-file %q: %v", c.CAFile, err)
		}
		f.Close()
	}
	if c.Demo && c.ListFile != "" {
		return fmt.Errorf("use either --demo or --list-file, not both")
	}
	switch c.Source {
	case "auto", "tranco", "umbrella", "file":
	default:
		return fmt.Errorf("invalid --source %q: must be auto, tranco, umbrella or file", c.Source)
	}
	if c.Pool < 1 || c.Pool > 5000 {
		return fmt.Errorf("invalid --pool %d: must be 1..5000", c.Pool)
	}
	if c.NativeShare < 1 || c.NativeShare > 100 {
		return fmt.Errorf("invalid --native-share %d: must be 1..100 (percent of the pool reserved for country-native domains)", c.NativeShare)
	}
	if !c.Demo {
		if c.Source == "file" && c.ListFile == "" {
			return fmt.Errorf("--source file requires --list-file <path>")
		}
		if c.Source != "file" && c.ListFile != "" {
			return fmt.Errorf("--list-file requires --source file (omit --source to fetch a list automatically)")
		}
	}
	return nil
}

func isLetters(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			return false
		}
	}
	return true
}

func parseListRuns(args []string) (*Config, error) {
	fs := newFlagSet()
	c := &Config{Subcommand: SubListRuns}
	fs.StringVar(&c.StoreDir, "store-dir", "runs", "")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("list-runs takes no positional arguments (got %q)", fs.Arg(0))
	}
	return c, nil
}

func parseExport(args []string) (*Config, error) {
	positional, values, err := parseTrailingFlags(args, map[string]bool{"output": true, "store-dir": true})
	if err != nil {
		return nil, err
	}
	if len(positional) != 1 {
		return nil, fmt.Errorf("export requires exactly one run-id argument (see --help)")
	}
	c := &Config{Subcommand: SubExport, RunID: positional[0], StoreDir: "runs", Output: OutputTable}
	if v, ok := values["store-dir"]; ok {
		c.StoreDir = v
	}
	if v, ok := values["output"]; ok {
		switch OutputFormat(v) {
		case OutputTable, OutputJSON, OutputXray:
			c.Output = OutputFormat(v)
		default:
			return nil, fmt.Errorf("invalid --output %q: must be table, json or xray-snippet", v)
		}
	}
	return c, nil
}

// parseTrailingFlags splits args into positional arguments and flags, allowing
// flags to be written after the positional run-id for export/validate.
func parseTrailingFlags(args []string, valueFlags map[string]bool) ([]string, map[string]string, error) {
	var positional []string
	values := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			key, val := name[:eq], name[eq+1:]
			if !valueFlags[key] {
				return nil, nil, fmt.Errorf("unknown flag %q (see --help)", "--"+key)
			}
			values[key] = val
			continue
		}
		if valueFlags[name] {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("flag --%s needs a value", name)
			}
			i++
			values[name] = args[i]
			continue
		}
		return nil, nil, fmt.Errorf("unknown flag %q (see --help)", a)
	}
	return positional, values, nil
}

func parseServe(args []string) (*Config, error) {
	fs := newFlagSet()
	c := &Config{Subcommand: SubServe}
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8787", "")
	fs.StringVar(&c.StoreDir, "store-dir", "runs", "")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("serve takes no positional arguments (got %q)", fs.Arg(0))
	}
	return c, nil
}

func parseValidate(args []string) (*Config, error) {
	positional, values, err := parseTrailingFlags(args, map[string]bool{"store-dir": true})
	if err != nil {
		return nil, err
	}
	if len(positional) != 1 {
		return nil, fmt.Errorf("validate requires exactly one run-id argument (see help)")
	}
	c := &Config{Subcommand: SubValidate, RunID: positional[0], StoreDir: "runs"}
	if v, ok := values["store-dir"]; ok {
		c.StoreDir = v
	}
	return c, nil
}

// LoadExtraRoots loads the --ca-file PEM into a cert pool, or returns nil.
func (c *Config) LoadExtraRoots() (*x509.CertPool, error) {
	if c.CAFile == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read --ca-file: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("--ca-file %q contains no usable PEM certificates", c.CAFile)
	}
	return pool, nil
}
