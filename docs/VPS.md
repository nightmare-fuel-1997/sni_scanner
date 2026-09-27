# Run on an Ubuntu VPS (one command + menu)

Fresh VPS (22.04 / 24.04):

```bash
sudo apt update && sudo apt install -y git golang-go
git clone <repo-url> sni-scanner && cd sni-scanner && ./run.sh
```

`./run.sh` checks Go ≥ 1.22, builds `bin/sni-scanner`
(`CGO_ENABLED=0`), then opens the interactive menu:

| # | Menu item | What it runs |
|---|---|---|
| 1 | Demo (table) | `--demo --output table` (offline) |
| 2 | Demo (json/xray) | `--demo --output <fmt>` (offline) |
| 3 | Auto scan | auto candidate sourcing, prompts for limit/max-rtt/pool/country |
| 4 | Auto scan — slow-link | same + `--concurrency 8 --timeout 20s`, higher `--max-rtt` default |
| 5 | File scan | `--source file --list-file <path>` |
| 6 | File scan — slow-link | file scan + slow-link preset |
| 7 | List runs | `list-runs` |
| 8 | Export run | `export <run-id> --output <fmt>` (no re-probing) |
| 9 | Validate run | `validate <run-id>` (re-probes passes) |
| 10 | Dashboard | `serve` in foreground; `Ctrl+C` returns to menu |
| 11 | Tests | `go vet ./...` + `go test ./...` |
| 12 | Update | `git pull --ff-only` + rebuild |
| 0 | Exit | — |

Notes:

- Power users: `EXTRA_ARGS="--verbose --country DE" ./run.sh` appends flags to every scan.
- Store: `STORE_DIR` env overrides the run store (default `./runs/`).
- Slow-link preset exists because throttled egress makes every probe time out
  at default concurrency — see README §4.6. If you see the timeout hint,
  use items 4 / 6 and raise `--max-rtt` to your observed RTT.
- Dashboard (`serve`) is read-only with no auth and defaults to
  `127.0.0.1:8787`. Do not bind `0.0.0.0` publicly without a reverse
  proxy + auth. On a remote VPS use `ssh -L 8787:127.0.0.1:8787 user@host`.
- Reset state: `rm -rf runs` then re-run the demo.
