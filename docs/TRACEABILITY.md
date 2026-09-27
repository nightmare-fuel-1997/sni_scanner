# Traceability — plan/document item → implementation

Source of truth: `REALITY-dest-scanner-plan.md` / `.html` (delivered 2026-09-21,
plan v1.0) plus the original specification `pasted_text_20260921-092744.txt`.

Status values: **Implemented** · **Deferred** (with reason) · **Changed** (with note).

## A. Architecture (§4 of the plan)

| Plan item | Implementation | Status |
|---|---|---|
| `cmd/` CLI entry + flags | `cmd/sni-scanner/main.go` | Implemented |
| `internal/geo` server self-identification | `internal/geo/geo.go` | Implemented |
| `internal/candidates` list + country filter | `internal/candidates/candidates.go` (`LoadFile`, `FilterCountry`) | Implemented |
| Automatic candidate sourcing from the host's geo/ASN | `internal/source/source.go` (`Build`, `fetchTranco`, `fetchUmbrella`, `selectForCountry`, `nativeSuffixes`) | **Added** — closes the plan's P1 gap where a hand-supplied list was required; Tranco + Umbrella with on-disk cache, country-native share and global fill |
| `internal/candidates` opt-in ASN neighbours | `internal/candidates/candidates.go` (`ASNFilter`, `FilterByASN`) | **Changed** — filters candidates against RIPE Stat published ASN data; probing arbitrary neighbour ranges is refused by design (see §3 of the plan) |
| `internal/probe` TLS + ALPN + chain + timing | `internal/probe/probe.go` | Implemented |
| `internal/probe` HTTP status + challenge disqualification | `internal/probe/http.go` | Implemented |
| `internal/rank` scoring/ordering | `internal/rank/rank.go` | Implemented |
| `internal/report` table / json / xray | `internal/report/table.go`, `json.go`, `xray.go` | Implemented |
| `internal/store` run cache/JSON store | `internal/store/store.go` | Implemented |
| Go, standard library only, static build | `go.mod` (no requires), `CGO_ENABLED=0` friendly | Implemented |
| Bounded concurrency + per-host caps | `probe.RunAll`, `hostLimiter`, `config.MaxConcurrency/MaxPerHost` | Implemented |
| Read-only results viewer over the store | `internal/web/server.go` + `serve` subcommand | **Added** — not in the plan; added to satisfy the delivery requirement for a user-facing interface. Read-only, no probing, default bind 127.0.0.1 |

## B. Validation pipeline (§5)

| Gate | Rule | Implementation | Status |
|---|---|---|---|
| G1 | TLS 1.3 + X25519 | `probe.go` handshake with `MaxVersion: TLS13`, `CurvePreferences: [X25519]` | Implemented |
| G2 | ALPN `h2` **and** `http/1.1` | two handshakes (h2-preferring + http/1.1-only) in `probe.Run` | Implemented |
| G3 | public CA chain, unexpired, not self-signed | `probe.makeVerifier` (`cert_selfsigned`, `cert_untrusted`, `cert_expired`, `cert_hostname`, `cert_chain`) | Implemented |
| G4 | `200` or same-site `301/302`; disqualify challenge/login/bot-block | `probe.classifyHTTP`, `hasLoginForm`, `firstMarker` | Implemented |
| G5 | RTT + jitter, DNS/TCP/TLS timed separately | `probe.Run` (median + stddev), `Options.MaxRTTms` | Implemented |
| Per-gate verdict with reason code | `probe.Verdict` on every `probe.Record` | Implemented |

## C. CLI contract (§6)

| Item | Implementation | Status |
|---|---|---|
| `--limit` (default 10) | `config.parseScan` | Implemented |
| `--max-rtt` | `config.parseScan`, enforced in `probe.Run` | Implemented |
| `--asn-only` (opt-in, off by default) | `config.parseScan`, `candidates.FilterByASN` | Implemented |
| `--output table\|json\|xray-snippet` | `config.parseScan`, `internal/report` | Implemented |
| Auto-sourcing flags `--source`, `--pool`, `--native-share`, `--refresh` | `config.parseScan`, `internal/source` | Added (superset of the spec; documented in README §4.6) |
| Slow-egress detection + tuning hint | `main.failureSummary` | Added after live testing showed aggressive defaults can time out on throttled hosts |
| Terminal table columns (exact set) | `report.Header` + `report.Table` | Implemented |
| Xray `dest` + `serverNames` snippet | `report.Xray` | Implemented (block only, never a whole config) |
| Extra flags (`--country`, `--list-file`, `--store-dir`, `--concurrency`, `--per-host`, `--timeout`, `--samples`, `--ca-file`, `--demo`, `--verbose`, `--version`) | `config` | Implemented (superset of the spec, each documented in README) |
| Subcommands `list-runs` / `export` / `validate` / `serve` | `main.go` | Implemented (`serve` is the added viewer) |

## D. Phases and milestones (§7 of the plan)

| Phase | Delivered evidence |
|---|---|
| P0 spec lock | This document + README §6–§7 |
| P1 geo + candidates | `internal/geo`, `internal/candidates` + tests |
| P1 automatic sourcing (was: user-supplied list only) | `internal/source` + tests (`source_test.go`, 8 tests) |
| P2 pipeline | `internal/probe` + fixture integration tests |
| P3 concurrency/perf | `probe.RunAll`, per-host limiter, `--concurrency`/`--per-host` |
| P4 CLI + output | `internal/config`, `internal/report` + renderer tests |
| P5 hardening/packaging | `CGO_ENABLED=0` clean, `.gitignore`, no secrets, `Makefile` |
| P6 verification/handoff | `README.md`, this file, `validate` re-check command |

## E. Verification plan (§13 of the plan)

| Plan check | Implementation |
|---|---|
| Fixture set with known outcomes | `internal/fixture` (4 servers) + `testdata/fixtures/expected-results.json` |
| Pipeline verdicts asserted, not just exit codes | `internal/probe/probe_test.go` |
| Benchmark of a larger run | **Deferred** — requires a real candidate set and network; measure on the target VPS with `--verbose` and the stored `results.json` |
| Output contract test (table/json/xray) | `internal/report/report_test.go` |
| Guardrail test (opt-in ASN mode, per-host caps) | `internal/candidates` ASN tests + `hostLimiter` in `probe.RunAll` |
| Field re-validation (24 h / 7 d drift) | `validate` subcommand; scheduling is the operator's step |

## F. Risk register (§9 of the plan) — where each mitigation landed

| Risk | Mitigation in code |
|---|---|
| R1 challenge pages pollute the shortlist | `classifyHTTP` markers + `login` form detection |
| R2 anycast/CDN, unstable RTT | pinned resolved IP per record; jitter recorded |
| R3 5–10 ms default unrealistic | `--max-rtt` is configurable; RTT distribution visible in `results.json` |
| R4 "<1 min" claim unproven | bounded concurrency; measure on the target host (deferred) |
| R5 geo-IP inaccuracy | `--country` override; provider fallback; source recorded |
| R6 list licence/ToS | tool consumes a local file only; no automatic downloads |
| R7 intrusive-scanning exposure | no range scanning; opt-in ASN filter; per-host caps; caps on concurrency/samples |
| R8 dest silently changes | `validate` subcommand + stored previous run for rollback |
| R9 measurement validity | DNS/TCP/TLS timed separately, N samples, jitter reported |
| R10 Go stdlib gaps | stdlib-only implementation builds and passes tests |
| R11 Xray snippet drift | snippet is emitted as a labelled block; loaded manually |

## G. Explicitly out of scope (per plan §2/§3 and the delivery brief)

- Executing the proxy configuration or writing into an existing Xray config.
- Production deployment, CI/CD, domain setup.
- Paid/credentialed third-party integrations.
- Real customer/personal data — all fixtures and sample data are synthetic.
