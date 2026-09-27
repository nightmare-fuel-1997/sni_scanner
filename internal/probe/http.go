package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"sni-scanner/internal/candidates"
)

// challengeMarkers are anti-bot / JS-challenge signatures. Their presence
// disqualifies a candidate: the plan never attempts to solve a challenge.
var challengeMarkers = []string{
	"just a moment",
	"cf-browser-verification",
	"challenge-platform",
	"cf_chl",
	"checking your browser",
	"enable javascript and cookies to continue",
	"ddos protection",
	"attention required",
	"captcha",
	"px-captcha",
	"datadome",
	"perimeterx",
	"incapsula incident",
	"you are being redirected to the waiting room",
}

// checkHTTP performs one polite GET / and returns (status, location, server,
// reasonCode, detail). An empty reasonCode means the gate passed.
func checkHTTP(ctx context.Context, c candidates.Candidate, o Options,
	verify func([][]byte, [][]*x509.Certificate) error) (int, string, string, string, string) {

	cfg := &tls.Config{
		ServerName:            c.Domain,
		NextProtos:            []string{"http/1.1"},
		MinVersion:            tls.VersionTLS12,
		MaxVersion:            tls.VersionTLS13,
		CurvePreferences:      []tls.CurveID{tls.X25519},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verify,
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: o.Timeout}
		raw, err := d.DialContext(ctx, "tcp", c.ConnectAddr)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, cfg)
		hctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		if err := conn.HandshakeContext(hctx); err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
	tr := &http.Transport{DialTLSContext: dial, DisableKeepAlives: true}
	client := &http.Client{
		Transport: tr,
		Timeout:   o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.Domain+"/", nil)
	if err != nil {
		return 0, "", "", "http_request", err.Error()
	}
	req.Header.Set("User-Agent", "sni-scanner/1.0 (+REALITY dest validation; benign TLS/HTTP capability check)")

	resp, err := client.Do(req)
	if err != nil {
		clean := err.Error()
		return 0, "", "", "http_error", clean
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	status := resp.StatusCode
	server := resp.Header.Get("Server")
	location := resp.Header.Get("Location")
	reason, detail := classifyHTTP(status, server, location, body, c.Domain)
	return status, location, server, reason, detail
}

// classifyHTTP applies the G4 rules: 200, or a same-site 301/302; challenge,
// login and bot-block pages are disqualified regardless of status.
func classifyHTTP(status int, server, location string, body []byte, domain string) (string, string) {
	low := strings.ToLower(string(body))

	if hasLoginForm(low) {
		return "login", "page renders a credential login form (disqualified by plan §5 G4)"
	}
	if marker := firstMarker(low); marker != "" {
		return "challenge", fmt.Sprintf("bot-challenge signature found in response body (%q)", marker)
	}
	if s := strings.ToLower(server); s != "" {
		for _, bad := range []string{"cloudflare", "ddos-guard", "sucuri", "imperva"} {
			if strings.Contains(s, bad) && (status == 403 || status == 429 || status == 503) {
				return "challenge", fmt.Sprintf("status %d with protective edge Server=%q", status, server)
			}
		}
	}

	switch status {
	case 200:
		return "", "200 OK"
	case 301, 302:
		if location == "" {
			return "http_redirect", fmt.Sprintf("status %d without a Location header", status)
		}
		if sameSite(location, domain) {
			return "", fmt.Sprintf("%d -> %s (same-site)", status, location)
		}
		return "http_redirect_cross_site", fmt.Sprintf("%d -> %s (cross-site redirect)", status, location)
	default:
		return "http_status", fmt.Sprintf("status %d is not 200/301/302", status)
	}
}

func hasLoginForm(lowBody string) bool {
	if !strings.Contains(lowBody, "<form") {
		return false
	}
	return strings.Contains(lowBody, "type=\"password\"") || strings.Contains(lowBody, "type='password'")
}

func firstMarker(lowBody string) string {
	for _, m := range challengeMarkers {
		if strings.Contains(lowBody, m) {
			return m
		}
	}
	return ""
}

func sameSite(location, domain string) bool {
	if strings.HasPrefix(location, "/") {
		return true
	}
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	if u.Scheme != "" && u.Scheme != "https" {
		return false
	}
	h := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	d := strings.TrimPrefix(strings.ToLower(domain), "www.")
	return h == d || strings.HasSuffix(h, "."+d)
}
