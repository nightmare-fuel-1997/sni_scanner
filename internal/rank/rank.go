// Package rank orders probe records so the best REALITY targets come first.
package rank

import (
	"sort"
	"strings"

	"sni-scanner/internal/probe"
)

// Sort orders records by: passing candidates first, then TLS handshake RTT,
// then jitter, then domain name. The ordering is stable and deterministic.
func Sort(records []probe.Record) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Pass != b.Pass {
			return a.Pass
		}
		if a.HandshakeMS != b.HandshakeMS {
			return a.HandshakeMS < b.HandshakeMS
		}
		if a.JitterMS != b.JitterMS {
			return a.JitterMS < b.JitterMS
		}
		return strings.ToLower(a.Domain) < strings.ToLower(b.Domain)
	})
}

// Passing returns the records that passed every gate, preserving input order.
func Passing(records []probe.Record) []probe.Record {
	out := make([]probe.Record, 0, len(records))
	for _, r := range records {
		if r.Pass {
			out = append(out, r)
		}
	}
	return out
}
