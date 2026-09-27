// Package web serves a small read-only dashboard over the run store so results
// can be reviewed in a browser. It is intentionally read-only: it never mutates
// stored records and never probes anything.
package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"sni-scanner/internal/probe"
	"sni-scanner/internal/store"
)

// Handler returns the dashboard HTTP handler.
func Handler(st *store.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		runs, err := st.List()
		if err != nil {
			httpError(w, err)
			return
		}
		render(w, indexTmpl, pageData{Title: "Runs", Runs: runs, Store: st.Dir})
	})
	mux.HandleFunc("/run/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/run/")
		if id == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		meta, records, err := st.Load(id)
		if err != nil {
			httpError(w, err)
			return
		}
		rows := buildRows(records)
		render(w, runTmpl, pageData{
			Title: "Run " + meta.RunID,
			Store: st.Dir,
			Run:   &meta,
			Rows:  rows,
			Total: len(records),
			FailN: len(records) - meta.PassedCount,
		})
	})
	mux.HandleFunc("/api/runs", func(w http.ResponseWriter, r *http.Request) {
		runs, err := st.List()
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(runs)
	})
	mux.HandleFunc("/api/run/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/run/")
		meta, records, err := st.Load(id)
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": meta, "results": records})
	})
	return mux
}

type pageData struct {
	Title string
	Store string
	Runs  []store.RunMeta
	Run   *store.RunMeta
	Rows  []Row
	Total int
	FailN int
}

// Row is a display projection of a probe record.
type Row struct {
	Domain      string
	IP          string
	TLSVersion  string
	ALPN        string
	RTT         string
	HTTPStatus  string
	Server      string
	Pass        bool
	Issuer      string
	ReasonCodes string
}

func buildRows(records []probe.Record) []Row {
	rows := make([]Row, 0, len(records))
	for _, r := range records {
		var reasons []string
		for _, v := range r.Verdicts {
			if !v.Pass && v.Reason != "" {
				reasons = append(reasons, v.Gate+":"+v.Reason)
			}
		}
		rows = append(rows, Row{
			Domain:      r.Domain,
			IP:          orDash(r.IP),
			TLSVersion:  orDash(r.TLSVersion),
			ALPN:        orDash(r.ALPN),
			RTT:         fmt.Sprintf("%.1f ms", r.HandshakeMS),
			HTTPStatus:  statusText(r.HTTPStatus),
			Server:      orDash(r.ServerHeader),
			Pass:        r.Pass,
			Issuer:      orDash(r.CertIssuer),
			ReasonCodes: strings.Join(reasons, ", "),
		})
	}
	return rows
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func statusText(s int) string {
	if s == 0 {
		return "—"
	}
	return fmt.Sprintf("%d", s)
}

func httpError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "not found: %v\n", err)
}

func render(w http.ResponseWriter, tmpl *template.Template, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		fmt.Fprintf(w, "template error: %v\n", err)
	}
}

const baseCSS = `
:root{
  --paper:#f4f2ee; --surface:#fbfaf7; --line:#e3ded4; --ink:#2c2a27;
  --ink-soft:#6b655c; --accent:#4f7a5b; --warn:#a2664f;
  --radius:16px; --shadow:0 1px 2px rgba(44,42,39,.04), 0 10px 24px rgba(44,42,39,.06);
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:"Segoe UI Variable Text","Segoe UI",-apple-system,"Helvetica Neue",Arial,sans-serif;
  line-height:1.55;font-size:15.5px}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 80px}
header.top{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin-bottom:6px}
h1{font-size:26px;font-weight:600;letter-spacing:-.01em;margin:0}
.sub{color:var(--ink-soft);font-size:13.5px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);padding:22px 24px;margin-top:22px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-top:22px}
.metric{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);padding:16px 18px}
.metric .k{font-size:11.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--ink-soft)}
.metric .v{font-size:24px;font-weight:600;margin-top:6px}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:14px}
th{text-align:left;font-weight:600;color:var(--ink-soft);font-size:11.5px;text-transform:uppercase;
  letter-spacing:.06em;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td.mono{font-variant-numeric:tabular-nums;color:var(--ink-soft)}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;border:1px solid transparent}
.pill.ok{background:#e7efe8;color:#33553c;border-color:#cddfd0}
.pill.no{background:#f5ebe6;color:#7d4b38;border-color:#e7d3c8}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.empty{padding:34px 6px;color:var(--ink-soft);text-align:center}
.foot{margin-top:26px;color:var(--ink-soft);font-size:12.5px}
code{background:#eeebe4;padding:2px 6px;border-radius:6px;font-size:13px}
`

var indexTmpl = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>sni-scanner — runs</title><style>` + baseCSS + `</style></head><body><div class="wrap">
<header class="top"><h1>sni-scanner</h1><span class="sub">REALITY dest/SNI runs · read-only dashboard</span></header>
<p class="sub">Stored runs from <code>{{.Store}}</code>. Newest first. This view never probes anything.</p>
<div class="card">
{{if .Runs}}
<table><thead><tr><th>Run ID</th><th>Started (UTC)</th><th>Country</th><th>ASN</th><th>Candidates</th><th>Passed</th></tr></thead><tbody>
{{range .Runs}}<tr>
<td><a href="/run/{{.RunID}}">{{.RunID}}</a></td>
<td class="mono">{{.StartedAt.Format "2006-01-02 15:04:05"}}</td>
<td>{{if .Geo.Country}}{{.Geo.Country}}{{else}}—{{end}}</td>
<td class="mono">{{if .Geo.ASN}}{{.Geo.ASN}}{{else}}—{{end}}</td>
<td class="mono">{{.CandidateCount}}</td>
<td class="mono">{{.PassedCount}}</td>
</tr>{{end}}
</tbody></table>
{{else}}
<div class="empty">No runs yet. Create one with <code>sni-scanner --demo</code> or <code>sni-scanner --list-file candidates.txt</code>.</div>
{{end}}
</div>
<p class="foot">JSON API: <a href="/api/runs">/api/runs</a> · read-only</p>
</div></body></html>`))

var runTmpl = template.Must(template.New("run").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>sni-scanner — {{.Run.RunID}}</title><style>` + baseCSS + `</style></head><body><div class="wrap">
<header class="top"><h1>Run {{.Run.RunID}}</h1><span class="sub"><a href="/">← all runs</a></span></header>
<p class="sub">Started {{.Run.StartedAt.Format "2006-01-02 15:04:05 UTC"}} · source {{if .Run.Geo.Source}}{{.Run.Geo.Source}}{{else}}unknown{{end}}{{if .Run.Note}} · {{.Run.Note}}{{end}}</p>
<div class="grid">
  <div class="metric"><div class="k">Candidates</div><div class="v">{{.Total}}</div></div>
  <div class="metric"><div class="k">Passed all gates</div><div class="v">{{.Run.PassedCount}}</div></div>
  <div class="metric"><div class="k">Disqualified</div><div class="v">{{.FailN}}</div></div>
  <div class="metric"><div class="k">Country / ASN</div><div class="v">{{if .Run.Geo.Country}}{{.Run.Geo.Country}}{{else}}—{{end}} {{if .Run.Geo.ASN}}<span class="sub">{{.Run.Geo.ASN}}</span>{{end}}</div></div>
</div>
<div class="card">
<table><thead><tr><th>Domain</th><th>IP Address</th><th>TLS Version</th><th>ALPN</th><th>Handshake RTT</th><th>HTTP</th><th>Server</th><th>Verdict</th><th>Failures</th></tr></thead><tbody>
{{range .Rows}}<tr>
<td>{{.Domain}}</td><td class="mono">{{.IP}}</td><td>{{.TLSVersion}}</td><td>{{.ALPN}}</td>
<td class="mono">{{.RTT}}</td><td class="mono">{{.HTTPStatus}}</td><td>{{.Server}}</td>
<td><span class="pill {{if .Pass}}ok{{else}}no{{end}}">{{if .Pass}}pass{{else}}fail{{end}}</span></td>
<td class="mono">{{if .ReasonCodes}}{{.ReasonCodes}}{{else}}—{{end}}</td>
</tr>{{end}}
</tbody></table>
</div>
<p class="foot">Raw record: <a href="/api/run/{{.Run.RunID}}">/api/run/{{.Run.RunID}}</a></p>
</div></body></html>`))
