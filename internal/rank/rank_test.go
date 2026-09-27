package rank

import (
	"testing"

	"sni-scanner/internal/probe"
)

func TestSortPassingFirstThenRTTThenJitter(t *testing.T) {
	in := []probe.Record{
		{Domain: "slow-pass.tld", Pass: true, HandshakeMS: 40, JitterMS: 1},
		{Domain: "fail-fast.tld", Pass: false, HandshakeMS: 5, JitterMS: 0},
		{Domain: "fast-pass.tld", Pass: true, HandshakeMS: 10, JitterMS: 0.5},
		{Domain: "jittery-pass.tld", Pass: true, HandshakeMS: 10, JitterMS: 3},
	}
	Sort(in)
	want := []string{"fast-pass.tld", "jittery-pass.tld", "slow-pass.tld", "fail-fast.tld"}
	for i, w := range want {
		if in[i].Domain != w {
			t.Fatalf("position %d: got %s, want %s", i, in[i].Domain, w)
		}
	}
}

func TestPassing(t *testing.T) {
	in := []probe.Record{{Domain: "a.tld", Pass: true}, {Domain: "b.tld"}, {Domain: "c.tld", Pass: true}}
	got := Passing(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 passing, got %d", len(got))
	}
}
