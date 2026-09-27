package report

import (
	"fmt"
	"strings"

	"sni-scanner/internal/probe"
)

// Xray renders a ready-to-paste Xray block for every candidate that passed all
// five gates (up to limit; 0 means no limit).
func Xray(records []probe.Record, limit int) string {
	passing := make([]probe.Record, 0, len(records))
	for _, r := range records {
		if r.Pass {
			passing = append(passing, r)
		}
	}
	if limit > 0 && len(passing) > limit {
		passing = passing[:limit]
	}
	if len(passing) == 0 {
		return "// no candidate passed all five gates; nothing to emit\n"
	}
	var b strings.Builder
	for i, r := range passing {
		fmt.Fprintf(&b, "// %d. %s — TLS handshake %.1f ms, HTTP %d, issuer %q\n",
			i+1, r.Domain, r.HandshakeMS, r.HTTPStatus, r.CertIssuer)
		b.WriteString("\"realitySettings\": {\n")
		fmt.Fprintf(&b, "  \"dest\": %q,\n", r.Domain+":443")
		fmt.Fprintf(&b, "  \"serverNames\": [%s]\n", quoteList(serverNames(r.Domain)))
		b.WriteString("}\n")
		if i < len(passing)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func serverNames(domain string) []string {
	if strings.HasPrefix(strings.ToLower(domain), "www.") {
		return []string{domain}
	}
	return []string{domain, "www." + domain}
}

func quoteList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, s := range items {
		quoted = append(quoted, fmt.Sprintf("%q", s))
	}
	return strings.Join(quoted, ", ")
}
