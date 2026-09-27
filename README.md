# sni-scanner

A lightweight, high-concurrency scanner that finds and validates **REALITY-ready
`dest` / `serverNames` targets** for Xray VLESS-REALITY inbounds.

It identifies the host's network position (country / city / IP / ASN), sources
candidate domains, runs every candidate through a five-gate TLS/HTTP validation
pipeline, ranks the survivors by handshake RTT and jitter, and emits a
copy-ready Xray snippet.

- **Language:** Go 1.22+, **standard library only** (no third-party modules, no `go.sum`).
- **Runs on:** Ubuntu / Debian / Alpine (static build with `CGO_ENABLED=0`), Windows, macOS.
- **No credentials, no paid APIs, no config files required.**

---

## 1. Safety and scope (read this first)

The tool performs **benign capability measurement of public TLS/HTTP endpoints**
— the same class of check as `openssl s_client` or a TLS test suite.

Intentionally **not implemented**, and out of scope:

- mass port scanning of third-party address space;
- logging in to, or interacting with, any target (forms, credentials, APIs);
- solving, retrying or evading anti-bot challenges (the scanner *detects and
  disqualifies* them);
- exploitation of any kind.

Guardrails are enforced in code: bounded global concurrency (`--concurrency`,
hard cap 512), a per-host cap (`--per-host`, hard cap 4), per-probe timeouts, and
same-ASN neighbour discovery that is **opt-in and off by default** (`--asn-only`
only *filters* candidates against published ASN data; it never scans ranges).

---

## 2. Requirements

| Requirement | Notes |
|---|---|
| Go 1.22 or newer | `go version` to check. Nothing else to install. |
| Optional: a candidate list | A local CSV/text file of domains (see §5). |
| Optional: internet access | Only for geo/ASN detection and for probing real domains. The demo and the test suite run fully offline. |

There are **no environment variables, secrets or config files** to set.

---

## 3. Install and run

**Ubuntu VPS (one command + menu):**

```bash
git clone <repo-url> sni-scanner && cd sni-scanner && ./run.sh
```

This builds the binary and opens an interactive menu (demo, auto/file
scans incl. slow-link presets, list/export/validate, dashboard, tests,
update). See `docs/VPS.md` for details.

```bash
# 1. build (from the repository root)
go build -o bin/sni-scanner ./cmd/sni-scanner

# 2. offline demo — probes bundled local TLS fixtures, no network traffic
./bin/sni-scanner --demo --output table

# 3. real scan against your own candidate list
./bin/sni-scanner --list-file candidates.txt --country IR --limit 10
```

On Windows use `bin\sni-scanner.exe`. `make build`, `make test`, `make run-demo`
are available if you prefer make.

### Stop

Every command is a short-lived process; stop it with `Ctrl+C`. The only
long-running command is the dashboard (`serve`, §4.5) — `Ctrl+C` shuts it down.

---

## 4. Commands

### 4.1 `sni-scanner` (scan)

Runs the full pipeline and stores the run. Flags:

| Flag | Default | Meaning |
|---|---|---|
| `--limit <n>` | `10` | Max domains in the ranked output (1–1000). |
| `--max-rtt <ms>` | `100` | Maximum median TLS handshake RTT for gate G5. |
| `--asn-only` | off | Keep only candidates whose IP is announced by the host's own ASN (opt-in). |
| `--output <fmt>` | `table` | `table`, `json` or `xray-snippet`. |
| `--country <cc>` | auto | Override the detected country (2-letter code); also applies the ccTLD filter. |
| `--source <s>` | `auto` | Candidate source: `auto` (Tranco → Umbrella), `tranco`, `umbrella`, or `file`. |
| `--list-file <path>` | — | Candidate list; requires `--source file` (§5). |
| `--pool <n>` | `200` | Max candidates built from the source (cap 5000). |
| `--native-share <pct>` | `50` | Percent of the pool reserved for country-native domains (1–100). |
| `--refresh` | off | Ignore the cached top-site list and re-download it. |
| `--store-dir <path>` | `runs` | Where runs are persisted. |
| `--concurrency <n>` | `64` | Global probe concurrency (cap 512). |
| `--per-host <n>` | `2` | Concurrent probes per host (cap 4). |
| `--timeout <dur>` | `10s` | Per-probe timeout. Raise this on slow links (see §4.6). |
| `--samples <n>` | `3` | Latency samples used for RTT/jitter (cap 10). |
| `--ca-file <pem>` | — | Extra root CA (PEM), for private CAs / the demo fixtures. |
| `--demo` | off | Probe bundled local fixtures, offline. |
| `--verbose` | off | Per-candidate progress on stderr. |
| `--version` | — | Print the version and exit. |

### 4.2 `sni-scanner list-runs`

Lists persisted runs (newest first) with timestamp, country, ASN, candidate and
pass counts.

### 4.3 `sni-scanner export <run-id> [--output fmt]`

Re-renders a stored run in any output format — no re-probing.

### 4.4 `sni-scanner validate <run-id>`

Re-probes the domains that passed in a stored run and stores the result as a new
run, with a clear per-domain reason list for anything that no longer passes.
This is the drill for detecting dests that silently changed (cert, ALPN, challenge).

### 4.5 `sni-scanner serve [--addr host:port] [--store-dir path]`

Starts a small **read-only** dashboard over the run store (default
`http://127.0.0.1:8787`): run list, per-run result table with verdicts, and JSON
endpoints `/api/runs` and `/api/run/<id>`. It never probes anything and never
writes to the store.

---

## 4.6 Automatic candidate sourcing (no list required)

With no extra flags, `sni-scanner` discovers its own candidates from the host it runs on:

1. **Detect the host** — public IP, country and ASN, via ip-api with an ipinfo fallback, cached on disk for an hour.
2. **Download a top-site list** — Tranco's latest list (cached at `<store-dir>/tranco-top1m.csv`; `--refresh` bypasses the cache). Cisco Umbrella's top-1M zip is the fallback when Tranco is unreachable.
3. **Select the pool** — reserve `--native-share` (default 50 %) of the pool for domains that look native to the detected country, then fill the remainder with the highest-ranked global entries, so a scan is never limited to a thin ccTLD slice.
4. **Probe, rank, store** — exactly the same pipeline as before.

**Country → native suffixes.** Most countries use their ccTLD (`.ir`, `.de`, `.fr`, …). The United States never adopted `.us` as a primary web TLD, so a US host uses the wider set `.us, .com, .org, .net, .gov, .edu`. Without that, a US run selects almost only Azure/TikTok infrastructure names — 12 of 40 had no DNS record at all — which is the failure this replaced.

Observed on the reference host (US, AS46475, 2026-09-21):

```
host: US AS46475 89.117.0.55 (ip-api.com)
source: tranco: fetched list 64X5X (250000 entries)
candidates: Tranco list 64X5X (15 native .us + 15 global fill, pool 30, native share 50%) — 30 domain(s)
gate failures: 24/30 disqualified (alpn_h2=1, cert_hostname=1, challenge=1, dns=6, handshake=12, http_redirect_cross_site=1, http_status=2)

Domain         | IP Address      | TLS Version | ALPN | Handshake RTT | HTTP Status | Server Header
instagram.com  | 57.144.198.34   | TLS 1.3     | h2   | 200.2 ms      | 301         | —
facebook.com   | 57.144.22.1     | TLS 1.3     | h2   | 202.1 ms      | 301         | —
cloudflare.com | 104.16.132.229  | TLS 1.3     | h2   | 202.6 ms      | 301         | cloudflare
gstatic.com    | 142.251.35.99   | TLS 1.3     | h2   | 206.5 ms      | 301         | sffe
google.com     | 192.178.50.46   | TLS 1.3     | h2   | 254.2 ms      | 301         | gws

run stored — 30 candidates probed, 6 passed all gates
```

### Tuning when the egress is slow or throttled

Some hosts have high-latency or throttled egress; too much concurrency then makes every probe time out, which can look like “nothing works”. The scanner detects that and says so, and it records the histogram in the run note:

```
hint: 8 probe(s) hit timeouts — this host's egress looks slow or throttled.
      Retry with --concurrency 8 --timeout 20s and raise --max-rtt to match the measured RTT.
```

Measured on the reference host: 60 candidates at `--concurrency 32` produced **0 passes** (individual handshakes took up to 15.2 s), while the same host at `--concurrency 3 --timeout 20s` passed **4 of 10**. Concurrency and timeout are the first knobs to try; `--max-rtt` should then be set from the RTT column you actually observe.

## 5. Candidate list format

```
# comment lines start with '#'
example.tld                      # domain only  → dials example.tld:443
5,ranked.example.tld             # rank,domain
addr.example.tld,127.0.0.1:8443  # domain,host:port (SNI = domain, dial target overridden)
7,full.example.tld,10.0.0.9:443  # rank,domain,host:port
```

The optional `host:port` form is what lets the scanner (and the demo/tests) talk
to an endpoint by IP while still using the real SNI and validating the
certificate against the domain name.

A synthetic sample list ships at `testdata/fixtures/sample-candidates.txt`.

---

## 6. Validation pipeline and reason codes

Every candidate gets a verdict for each of the five gates; failures always carry
a machine-readable reason code.

| Gate | Check | Pass | Example failure reasons |
|---|---|---|---|
| **G1** | TLS 1.3 negotiated, X25519 key share | TLS 1.3 | `tls_version`, `handshake` |
| **G2** | ALPN negotiates `h2` **and** `http/1.1` | both | `alpn_h2`, `alpn_http11` |
| **G3** | Certificate on a trusted chain, unexpired, not self-signed | valid chain | `cert_selfsigned`, `cert_untrusted`, `cert_expired`, `cert_hostname`, `cert_chain` |
| **G4** | One polite `GET /`: `200`, or same-site `301/302`; no challenge/login page | 200 / same-site redirect | `challenge`, `login`, `http_status`, `http_redirect_cross_site` |
| **G5** | Median TLS handshake RTT ≤ `--max-rtt`, jitter reported | within limit | `rtt`, `handshake` |

Note on G2: ALPN is checked with **two** handshakes (one preferring `h2`, one
offering only `http/1.1`), because a single handshake only reveals the one
protocol the server picks.

---

## 7. Output

`--output table` (exact columns from the plan):

```
Domain                    | IP Address | TLS Version | ALPN     | Handshake RTT | HTTP Status | Server Header
--------------------------+------------+-------------+----------+---------------+-------------+--------------
edge-native-demo.tld      | 127.0.0.1  | TLS 1.3     | h2       | 1.7 ms        | 200         | —
```

`--output json` includes every gate verdict and reason code. `--output
xray-snippet` prints one ready-to-paste block per *passing* candidate:

```json
"realitySettings": {
  "dest": "edge-native-demo.tld:443",
  "serverNames": ["edge-native-demo.tld", "www.edge-native-demo.tld"]
}
```

---

## 8. Data model and persistence

Each run is written atomically to `<store-dir>/<run-id>/`:

| File | Contents |
|---|---|
| `run.json` | `run_id`, `started_at` (UTC), `flags`, detected `geo` (ip/city/country/asn/source), `candidate_count`, `passed_count`, `note` |
| `results.json` | Every candidate record: domain, IP, TLS version, ALPN, cert metadata, HTTP status, timings, per-gate verdicts |

Run IDs look like `20260921-074853-389fe9` (UTC timestamp + random suffix).
Records survive restarts; read them back with `list-runs`, `export`, or the
dashboard. Deleting a run directory is the only way to remove a record.

**Reset to a clean state:** delete the `runs/` directory (`rm -rf runs` on Linux,
`Remove-Item -Recurse -Force runs` on Windows) and re-run `--demo`.

---

## 9. Architecture

```
cmd/sni-scanner/        CLI entry point, subcommand dispatch, wiring
internal/config/        flag parsing, validation, usage text
internal/geo/           IP/city/country/ASN detection (ip-api → ipinfo, cached, degrades offline)
internal/candidates/    list parsing, ccTLD filter, opt-in ASN filter (RIPE Stat)
internal/probe/         the five gates: tls.go (G1–G3, G5 timing) and http.go (G4)
internal/rank/          pass-first ordering by RTT then jitter
internal/report/        table / json / xray-snippet renderers
internal/store/         run persistence (atomic JSON writes)
internal/fixture/       local TLS fixtures used by --demo and the tests
internal/web/           read-only dashboard over the store
testdata/fixtures/      sample candidate list + expected results
```

Data flows one way: `candidates → probe → rank → report → store`, with `web`
reading the store.

---

## 10. Tests

```bash
go test ./...        # single documented command
go vet ./...
```

The suite is **offline and deterministic**: the integration tests start their own
local TLS servers (via `internal/fixture`) and never touch the network.

Coverage includes: list parsing and its error cases, ccTLD and ASN filtering,
ranking order, all three renderers, the store round-trip across a simulated
restart, geo provider parsing/fallback/cache, the G1–G5 pipeline against
pass / TLS-1.2 / self-signed / challenge / login fixtures, the G4 heuristics as a
table test, DNS-failure handling, and the dashboard index/detail/API/404 paths.

---

## 11. Known limitations and deferred items

| Item | Status | Reason |
|---|---|---|
| Automatic Tranco / Cisco Umbrella download | Implemented | `--source auto` (default) fetches Tranco with Umbrella as fallback; lists are cached locally and licences/rate limits are respected by fetching at most once per day. |
| Same-ASN **neighbour IP-range discovery and probing** | Not implemented (deliberate) | Would amount to scanning third-party ranges; `--asn-only` filters candidates against published ASN data instead. |
| Offline GeoIP database | Deferred | Geo/ASN currently uses online providers with a 1-hour on-disk cache; go offline → detection is skipped with a note, the scan still runs. |
| Full Xray config emission | Not implemented (deliberate) | The tool emits the `realitySettings` block only, so it cannot overwrite an operator's config. |
| Dashboard authentication | Not implemented | The dashboard is read-only and binds to `127.0.0.1` by default; do not expose it publicly without adding auth. |
| Retention/rotation of old runs | Not implemented | Delete run directories manually; nothing is removed automatically. |

---

## 12. Recommended next steps

1. Point `--list-file` at a Tranco/Umbrella export filtered to your country and
   run against your VPS to get a real shortlist.
2. Set `--max-rtt` from the actual RTT distribution in the run's `results.json`.
3. Schedule `validate <run-id>` (cron/systemd timer) to detect dests that drift.
4. If you want neighbour discovery, design it deliberately as an allowlisted,
   rate-limited feature — the current build refuses it by design.

See `docs/TRACEABILITY.md` for the requirement-by-requirement mapping against the
planning documents.
