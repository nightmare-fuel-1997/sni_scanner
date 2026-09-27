// Package report renders scan results as a terminal table, JSON or an
// Xray-ready dest/serverNames snippet.
package report

import (
	"fmt"
	"strconv"
	"strings"

	"sni-scanner/internal/probe"
)

// Header is the exact column set required by the plan.
var Header = []string{"Domain", "IP Address", "TLS Version", "ALPN", "Handshake RTT", "HTTP Status", "Server Header"}

// Table renders up to limit records as a fixed-width text table.
// A limit of 0 means "no limit".
func Table(records []probe.Record, limit int) string {
	rows := records
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	cells := make([][]string, 0, len(rows)+1)
	cells = append(cells, append([]string(nil), Header...))
	for _, r := range rows {
		cells = append(cells, []string{
			r.Domain,
			dash(r.IP),
			dash(r.TLSVersion),
			dash(r.ALPN),
			fmt.Sprintf("%.1f ms", r.HandshakeMS),
			statusCell(r.HTTPStatus),
			dash(r.ServerHeader),
		})
	}

	widths := make([]int, len(Header))
	for _, row := range cells {
		for i, c := range row {
			if n := len([]rune(c)); n > widths[i] {
				widths[i] = n
			}
		}
	}

	var b strings.Builder
	for i, row := range cells {
		for j, c := range row {
			b.WriteString(padRight(c, widths[j]))
			if j < len(row)-1 {
				b.WriteString(" | ")
			}
		}
		b.WriteByte('\n')
		if i == 0 {
			for j := range row {
				b.WriteString(strings.Repeat("-", widths[j]))
				if j < len(row)-1 {
					b.WriteString("-+-")
				}
			}
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func padRight(s string, width int) string {
	n := len([]rune(s))
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func statusCell(status int) string {
	if status == 0 {
		return "—"
	}
	return strconv.Itoa(status)
}
