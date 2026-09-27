package config

import (
	"strings"
	"testing"
)

func TestParseScanValid(t *testing.T) {
	cfg, err := Parse([]string{"--source", "file", "--list-file", "candidates.txt", "--limit", "5", "--output", "json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Limit != 5 || cfg.Output != OutputJSON || cfg.Subcommand != SubScan || cfg.Source != "file" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Concurrency != 64 || cfg.PerHost != 2 || cfg.Samples != 3 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestParseScanAutoSource(t *testing.T) {
	cfg, err := Parse([]string{"--pool", "50"})
	if err != nil {
		t.Fatalf("automatic sourcing should need no list file: %v", err)
	}
	if cfg.Source != "auto" || cfg.Pool != 50 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseVersionNeedsNoListFile(t *testing.T) {
	cfg, err := Parse([]string{"--version"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Version {
		t.Fatal("expected Version=true")
	}
}

func TestValidationErrors(t *testing.T) {
	fileArgs := func(extra ...string) []string {
		return append([]string{"--source", "file", "--list-file", "x.txt"}, extra...)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown source", []string{"--source", "bogus"}, "invalid --source"},
		{"file source without list-file", []string{"--source", "file"}, "--source file requires"},
		{"list-file without file source", []string{"--list-file", "x.txt"}, "requires --source file"},
		{"demo plus list file", []string{"--demo", "--list-file", "x.txt"}, "either --demo or --list-file"},
		{"bad output", fileArgs("--output", "csv"), "invalid --output"},
		{"zero limit", fileArgs("--limit", "0"), "invalid --limit"},
		{"bad max-rtt", fileArgs("--max-rtt", "0"), "invalid --max-rtt"},
		{"bad concurrency", fileArgs("--concurrency", "9999"), "invalid --concurrency"},
		{"bad per-host", fileArgs("--per-host", "9"), "invalid --per-host"},
		{"bad samples", fileArgs("--samples", "99"), "invalid --samples"},
		{"bad pool", fileArgs("--pool", "0"), "invalid --pool"},
		{"bad native share", fileArgs("--native-share", "0"), "invalid --native-share"},
		{"bad country", fileArgs("--country", "IRN"), "invalid --country"},
		{"unknown flag", fileArgs("--nope"), "flag provided but not defined"},
		{"stray positional", fileArgs("extra"), "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.args)
			if err == nil {
				t.Fatalf("expected error for %v", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestSubcommands(t *testing.T) {
	cfg, err := Parse([]string{"list-runs"})
	if err != nil || cfg.Subcommand != SubListRuns {
		t.Fatalf("list-runs parse failed: %v %+v", err, cfg)
	}
	cfg, err = Parse([]string{"export", "20260101-000000-abc123", "--output", "xray-snippet"})
	if err != nil {
		t.Fatalf("export parse failed: %v", err)
	}
	if cfg.RunID != "20260101-000000-abc123" || cfg.Output != OutputXray {
		t.Fatalf("unexpected export config: %+v", cfg)
	}
	if _, err := Parse([]string{"export"}); err == nil {
		t.Fatal("export without run-id should fail")
	}
	cfg, err = Parse([]string{"serve"})
	if err != nil || cfg.Subcommand != SubServe || cfg.Addr == "" {
		t.Fatalf("serve parse failed: %v %+v", err, cfg)
	}
	if _, err := Parse([]string{"validate"}); err == nil {
		t.Fatal("validate without run-id should fail")
	}
}
