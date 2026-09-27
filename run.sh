#!/usr/bin/env bash
# sni-scanner — one-command VPS launcher with interactive menu.
# Usage on a fresh Ubuntu VPS:
#   git clone <repo-url> sni-scanner && cd sni-scanner && ./run.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$ROOT_DIR/bin/sni-scanner"
STORE_DIR="${STORE_DIR:-$ROOT_DIR/runs}"
# Power users: EXTRA_ARGS is appended to every scan invocation, e.g.
#   EXTRA_ARGS="--verbose --country DE" ./run.sh
EXTRA_ARGS="${EXTRA_ARGS:-}"

msg()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

check_go() {
  if ! command -v go >/dev/null 2>&1; then
    die "Go not found. On Ubuntu run: sudo apt update && sudo apt install -y golang-go  (needs Go 1.22+). Then re-run ./run.sh"
  fi
  local ver raw major minor
  raw="$(go version | awk '{print $3}')"   # e.g. go1.22.4
  ver="${raw#go}"
  major="${ver%%.*}"
  minor="$(echo "$ver" | cut -d. -f2)"
  if [ "${major:-0}" -lt 1 ] || { [ "$major" -eq 1 ] && [ "${minor:-0}" -lt 22 ]; }; then
    die "Go $ver too old (need 1.22+). On Ubuntu 22.04 the apt Go may be old — use snap (sudo snap install go --classic) or https://go.dev/dl/. Then re-run ./run.sh"
  fi
}

build() {
  mkdir -p "$ROOT_DIR/bin" "$STORE_DIR"
  msg "building sni-scanner..."
  CGO_ENABLED=0 go build -o "$BIN" ./cmd/sni-scanner
  msg "build ok: $BIN"
}

pause() { read -rp "Press Enter to return to the menu..." _; }

prompt_with_default() {
  # $1=prompt text, $2=default -> echoes value
  local text="$1" def="$2" ans
  read -rp "$text [$def]: " ans
  if [ -z "${ans:-}" ]; then echo "$def"; else echo "$ans"; fi
}

prompt_yes_no() {
  # $1=prompt, $2=default y/n -> echoes y or n
  local text="$1" def="$2" ans
  read -rp "$text [$def]: " ans
  ans="${ans:-$def}"
  case "$ans" in
    [Yy]*) echo "y" ;; *) echo "n" ;; esac
}

run_scan() {
  # $@ = extra scan flags (already assembled)
  # shellcheck disable=SC2086
  "$BIN" --store-dir "$STORE_DIR" "$@" $EXTRA_ARGS
}

demo_table() {
  msg "--- demo (offline, table) ---"
  run_scan --demo --output table
  pause
}

demo_other() {
  local fmt
  fmt="$(prompt_with_default "Output format (table/json/xray-snippet)" "json")"
  msg "--- demo (offline, $fmt) ---"
  run_scan --demo --output "$fmt"
  pause
}

scan_auto() {
  local limit maxrtt pool country output asn
  limit="$(prompt_with_default "Max domains in output (--limit 1-1000)" "10")"
  maxrtt="$(prompt_with_default "Max handshake RTT ms (--max-rtt)" "100")"
  pool="$(prompt_with_default "Candidate pool size (--pool 1-5000)" "200")"
  country="$(prompt_with_default "Country override 2-letter code (empty = auto-detect)" "")"
  output="$(prompt_with_default "Output (table/json/xray-snippet)" "table")"
  asn="$(prompt_yes_no "Restrict to own ASN (--asn-only)? y/n" "n")"
  local args=(--limit "$limit" --max-rtt "$maxrtt" --pool "$pool" --output "$output")
  [ -n "$country" ] && args+=(--country "$country")
  [ "$asn" = "y" ] && args+=(--asn-only)
  msg "--- auto scan ---"
  run_scan "${args[@]}"
  pause
}

scan_auto_slow() {
  # Preset for throttled / high-latency egress (README §4.6).
  local limit maxrtt pool country output
  limit="$(prompt_with_default "Max domains in output (--limit 1-1000)" "10")"
  maxrtt="$(prompt_with_default "Max handshake RTT ms (raise to match observed RTT, e.g. 1000)" "1000")"
  pool="$(prompt_with_default "Candidate pool size (--pool 1-5000)" "30")"
  country="$(prompt_with_default "Country override 2-letter code (empty = auto-detect)" "")"
  output="$(prompt_with_default "Output (table/json/xray-snippet)" "table")"
  msg "slow-link preset: --concurrency 8 --timeout 20s (README §4.6)"
  local args=(--limit "$limit" --max-rtt "$maxrtt" --pool "$pool" --output "$output"
    --concurrency 8 --timeout 20s)
  [ -n "$country" ] && args+=(--country "$country")
  msg "--- auto scan (slow-link) ---"
  run_scan "${args[@]}"
  pause
}

scan_file() {
  local file limit maxrtt output country asn
  read -rp "Candidate list path (--list-file): " file
  [ -z "${file:-}" ] && { warn "no file given."; pause; return; }
  [ -f "$file" ] || { warn "file not found: $file"; pause; return; }
  limit="$(prompt_with_default "Max domains in output (--limit 1-1000)" "10")"
  maxrtt="$(prompt_with_default "Max handshake RTT ms (--max-rtt)" "100")"
  output="$(prompt_with_default "Output (table/json/xray-snippet)" "table")"
  country="$(prompt_with_default "Country override 2-letter code (empty = auto-detect)" "")"
  asn="$(prompt_yes_no "Restrict to own ASN (--asn-only)? y/n" "n")"
  local args=(--source file --list-file "$file" --limit "$limit" --max-rtt "$maxrtt" --output "$output")
  [ -n "$country" ] && args+=(--country "$country")
  [ "$asn" = "y" ] && args+=(--asn-only)
  msg "--- file scan ---"
  run_scan "${args[@]}"
  pause
}

scan_file_slow() {
  local file limit maxrtt output
  read -rp "Candidate list path (--list-file): " file
  [ -z "${file:-}" ] && { warn "no file given."; pause; return; }
  [ -f "$file" ] || { warn "file not found: $file"; pause; return; }
  limit="$(prompt_with_default "Max domains in output (--limit 1-1000)" "10")"
  maxrtt="$(prompt_with_default "Max handshake RTT ms (raise to match observed RTT, e.g. 1000)" "1000")"
  output="$(prompt_with_default "Output (table/json/xray-snippet)" "table")"
  msg "slow-link preset: --concurrency 8 --timeout 20s (README §4.6)"
  msg "--- file scan (slow-link) ---"
  run_scan --source file --list-file "$file" --limit "$limit" --max-rtt "$maxrtt" \
    --output "$output" --concurrency 8 --timeout 20s
  pause
}

list_runs() {
  msg "--- persisted runs (newest first) ---"
  "$BIN" list-runs --store-dir "$STORE_DIR"
  pause
}

export_run() {
  local id fmt
  read -rp "Run ID to export: " id
  [ -z "${id:-}" ] && { warn "no run-id given."; pause; return; }
  fmt="$(prompt_with_default "Output format (table/json/xray-snippet)" "table")"
  "$BIN" export "$id" --output "$fmt" --store-dir "$STORE_DIR"
  pause
}

validate_run() {
  local id
  read -rp "Run ID to re-validate: " id
  [ -z "${id:-}" ] && { warn "no run-id given."; pause; return; }
  "$BIN" validate "$id" --store-dir "$STORE_DIR"
  pause
}

serve_dashboard() {
  local addr
  addr="$(prompt_with_default "Bind address (--addr)" "127.0.0.1:8787")"
  case "$addr" in
    0.0.0.0*|*:8787|"[::]"*)
      warn "dashboard has NO auth and is read-only — do not expose $addr publicly without a reverse proxy + auth (README §11)."
      ;;
  esac
  msg "starting dashboard (foreground) — press Ctrl+C to return to the menu."
  # Foreground on purpose: Ctrl+C stops serve and drops back to the menu.
  "$BIN" serve --addr "$addr" --store-dir "$STORE_DIR"
  msg "dashboard stopped."
  pause
}

run_tests() {
  msg "--- go vet + go test ---"
  go vet ./...
  go test ./...
  pause
}

update_repo() {
  msg "--- git pull + rebuild ---"
  git -C "$ROOT_DIR" pull --ff-only
  build
  pause
}

print_menu() {
  cat <<'EOF'

  sni-scanner — VPS menu
  ======================
   1) Demo (offline, table)
   2) Demo (json / xray-snippet)
   3) Auto scan (defaults)
   4) Auto scan — slow-link preset (concurrency 8, timeout 20s)
   5) File scan
   6) File scan — slow-link preset
   7) List runs
   8) Export run
   9) Validate run (re-probe passes)
  10) Dashboard (foreground, Ctrl+C to return)
  11) Tests (vet + test)
  12) Update (git pull + rebuild)
   0) Exit
EOF
}

main() {
  check_go
  build
  while true; do
    print_menu
    read -rp "Choose [0-12]: " choice
    case "${choice:-}" in
      1) demo_table ;;
      2) demo_other ;;
      3) scan_auto ;;
      4) scan_auto_slow ;;
      5) scan_file ;;
      6) scan_file_slow ;;
      7) list_runs ;;
      8) export_run ;;
      9) validate_run ;;
      10) serve_dashboard ;;
      11) run_tests ;;
      12) update_repo ;;
      0|q|quit|exit) msg "bye."; exit 0 ;;
      *) warn "unknown choice: $choice" ;;
    esac
  done
}

main "$@"
