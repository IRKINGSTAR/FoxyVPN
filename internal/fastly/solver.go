// Solves Fastly client challenges (pow / pat / client metrics) served as
// HTTP 406 by the Mozilla control plane, and installs the cookies.
package fastly

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"foxyvpn/internal/controlplane"
	"foxyvpn/internal/logx"
	"foxyvpn/internal/remoteconfig"
)

const tag = "FastlySolver"

const solveTimeout = 90 * time.Second
const maxPostBackRounds = 8

const powAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

const htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

var (
	challengePrefixRe = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
	initCallRe        = regexp.MustCompile(`\binit\s*\(\s*\[`)
)

// Error is returned when a challenge could not be solved.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

var solverMu sync.Mutex

var mozillaHosts = []string{
	"api.accounts.firefox.com",
	"accounts.firefox.com",
	"oauth.accounts.firefox.com",
	"vpn.mozilla.org",
}

// SolveAndInstall: solve the body directly when it is a challenge page,
// otherwise probe the known hosts.
func SolveAndInstall(challengedBody, challengedOrigin, userAgent string) error {
	solverMu.Lock()
	defer solverMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- solve(challengedBody, challengedOrigin, userAgent) }()
	select {
	case err := <-done:
		return err
	case <-time.After(solveTimeout + 10*time.Second):
		return &Error{Msg: "challenge solving timed out"}
	}
}

func solve(challengedBody, challengedOrigin, userAgent string) error {
	origin := challengedOrigin
	if origin == "" {
		origin = "https://api.accounts.firefox.com"
	}
	u, err := url.Parse(origin)
	if err != nil {
		return &Error{Msg: "invalid challenge origin"}
	}
	validHost := false
	for _, h := range mozillaHosts {
		if strings.EqualFold(u.Hostname(), h) {
			validHost = true
			break
		}
	}
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") || u.User != nil || !validHost {
		return &Error{Msg: "untrusted challenge origin"}
	}
	base := "https://" + u.Hostname()
	if challengedBody != "" && isChallengePage(challengedBody) {
		jar := controlplane.NewCookieJar()
		solver := newSolverClient(jar)
		return solveChallengePage(challengedBody, base, userAgent, solver, jar)
	}
	bases := []string{base, "https://api.accounts.firefox.com", "https://accounts.firefox.com"}
	seen := map[string]bool{}
	var lastErr error
	for _, candidateBase := range bases {
		if seen[candidateBase] {
			continue
		}
		seen[candidateBase] = true
		agents := []string{userAgent, browserUA(), desktopUA()}
		deduped := dedupe(agents)
		for _, candidateUA := range deduped {
			ok, err := solveChallengeOnHost(candidateBase, candidateUA)
			if ok {
				return nil
			}
			if err != nil {
				lastErr = err
			}
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return &Error{Msg: "host did not serve a Fastly challenge page"}
}

func browserUA() string { return remoteconfig.BrowserUserAgent() }

func desktopUA() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0"
}

func dedupe(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func baseOrigin(prefixURL string) string {
	idx := strings.Index(prefixURL, "/_fs-ch-")
	if idx > 0 {
		return prefixURL[:idx]
	}
	return prefixURL
}

func solvePow(base, targetHex string) (string, error) {
	if len(targetHex) != 64 {
		return "", &Error{Msg: "invalid pow target"}
	}
	var target [32]byte
	for i := 0; i < 32; i++ {
		var b int
		if _, err := fmt.Sscanf(targetHex[i*2:i*2+2], "%02x", &b); err != nil {
			return "", &Error{Msg: "invalid pow target hex"}
		}
		target[i] = byte(b)
	}
	for _, a := range powAlphabet {
		for _, b := range powAlphabet {
			suffix := string(a) + string(b)
			sum := sha256.Sum256([]byte(base + suffix))
			if bytes.Equal(sum[:], target[:]) {
				return suffix, nil
			}
		}
	}
	return "", &Error{Msg: "no proof-of-work solution found for base " + base}
}

func fetchText(client *http.Client, url, accept, userAgent string, allowChallenge bool) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range remoteconfig.SolverHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	if err != nil {
		return "", err
	}
	text := string(body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if !(allowChallenge && isChallengePage(text)) {
			return "", &Error{Msg: fmt.Sprintf("challenge page returned HTTP %d", resp.StatusCode)}
		}
	}
	return text, nil
}

func isChallengePage(text string) bool {
	return len(text) >= 1 && len(text) <= 2_000_000 &&
		challengePrefixRe.MatchString(text) &&
		(strings.Contains(strings.ToLower(text), "client challenge") ||
			strings.Contains(text, "script.js") ||
			strings.Contains(text, "fst-post-back"))
}

// parseChallengeInit reads init([challenges], "token" [, "prefix"]).
func parseChallengeInit(script, prefix string) ([]map[string]any, string, error) {
	matches := initCallRe.FindAllStringIndex(script, -1)
	var legacyCh []map[string]any
	var legacyTok string
	legacyOK := false
	for i := len(matches) - 1; i >= 0; i-- {
		start := matches[i][1] - 1 // position of '['
		if start < 0 || start >= len(script) || script[start] != '[' {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(script[start:]))
		var challenges []map[string]any
		if err := dec.Decode(&challenges); err != nil || len(challenges) == 0 || len(challenges) > 16 {
			continue
		}
		if !challengesValid(challenges) {
			continue
		}
		rest, ok := skipSpace(script[start:], dec.InputOffset())
		if !ok || !strings.HasPrefix(rest, ",") {
			continue
		}
		var token string
		if err := dec.Decode(&token); err != nil || strings.TrimSpace(token) == "" {
			continue
		}
		rest, ok = skipSpace(script[start:], dec.InputOffset())
		if !ok {
			continue
		}
		if strings.HasPrefix(rest, ",") {
			var scriptPrefix string
			if err := dec.Decode(&scriptPrefix); err != nil {
				continue
			}
			rest, ok = skipSpace(script[start:], dec.InputOffset())
			if !ok || !(strings.HasPrefix(rest, ")") || strings.HasPrefix(rest, ",")) {
				continue
			}
			if prefix == "" || scriptPrefix == prefix {
				return challenges, token, nil
			}
		} else if strings.HasPrefix(rest, ")") {
			if !legacyOK {
				legacyCh, legacyTok, legacyOK = challenges, token, true
			}
		}
	}
	if legacyOK {
		return legacyCh, legacyTok, nil
	}
	return nil, "", &Error{Msg: "could not read the Fastly challenge"}
}

func skipSpace(s string, offset int64) (string, bool) {
	if offset < 0 || int(offset) > len(s) {
		return "", false
	}
	return strings.TrimLeft(s[int(offset):], " \t\r\n"), true
}

func challengesValid(challenges []map[string]any) bool {
	for _, item := range challenges {
		if item == nil {
			return false
		}
		ty, _ := item["ty"].(string)
		if strings.TrimSpace(ty) == "" {
			return false
		}
	}
	return true
}

type patResponse struct {
	Auth string `json:"auth"`
}

func fetchPat(client *http.Client, prefixURL, token, userAgent string) (string, error) {
	patURL := prefixURL + "/pat?token=" + url.QueryEscape(token)
	req, err := http.NewRequest("POST", patURL, bytes.NewReader(nil))
	if err != nil {
		return "", err
	}
	for k, v := range remoteconfig.SolverHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", baseOrigin(prefixURL))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 400 || resp.StatusCode == 401 {
		return "", nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &Error{Msg: fmt.Sprintf("PAT request returned HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", &Error{Msg: "could not parse PAT response"}
	}
	var pr patResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		return "", &Error{Msg: "could not parse PAT response"}
	}
	if pr.Auth == "" {
		return "", &Error{Msg: "empty PAT auth token"}
	}
	return pr.Auth, nil
}

func clientMetricsAnswer() map[string]any {
	return map[string]any{
		"ty":       "clientmetrics",
		"webdriver": false,
		"bot_detection_result": map[string]any{
			"bot_detected": false,
			"bot_kind":     nil,
		},
		"browser_metrics": map[string]any{
			"client_data": "{}",
			"error_trace": nil,
		},
		"detector_results": map[string]any{},
		"v":                2,
	}
}

func answerChallenge(client *http.Client, prefixURL, token string, challenge map[string]any, userAgent string) (map[string]any, error) {
	ty, _ := challenge["ty"].(string)
	data, _ := challenge["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	switch ty {
	case "pow":
		base, _ := data["base"].(string)
		hash, _ := data["hash"].(string)
		answer, err := solvePow(base, hash)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"ty":      "pow",
			"base":    base,
			"answer":  answer,
			"hmac":    fmt.Sprintf("%v", data["hmac"]),
			"expires": fmt.Sprintf("%v", data["expires"]),
		}, nil
	case "pat":
		auth, err := fetchPat(client, prefixURL, token, userAgent)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ty": "pat", "auth": auth}, nil
	case "clientmetrics":
		return clientMetricsAnswer(), nil
	case "captcha":
		return nil, &Error{Msg: "Firefox Accounts requires a CAPTCHA. Sign in again to continue."}
	default:
		return nil, &Error{Msg: fmt.Sprintf("unsupported Fastly challenge type '%s'", ty)}
	}
}

func installChallengeCookies(jar *controlplane.CookieJar) error {
	cookies := jar.SnapshotAll()
	if len(cookies) == 0 {
		return &Error{Msg: "challenge completed but no cookies were issued"}
	}
	for _, cookie := range cookies {
		hostClean := strings.TrimPrefix(cookie.Domain, ".")
		if hostClean != "" {
			jar.InstallForced(*cookie, []string{hostClean})
		}
		if strings.HasSuffix(hostClean, "firefox.com") {
			domainCookie := *cookie
			domainCookie.Domain = "firefox.com"
			domainCookie.Path = "/"
			jar.InstallForced(domainCookie, []string{"firefox.com"})
		}
		jar.InstallForced(*cookie, mozillaHosts)
	}
	return nil
}

func newSolverClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport: controlplane.NewFirefoxTLSTransport(),
		Jar:       jar,
		Timeout:   solveTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func solveChallengeOnHost(base, userAgent string) (bool, error) {
	jar := controlplane.NewCookieJar()
	solver := newSolverClient(jar)
	page, err := fetchText(solver, base+"/", htmlAccept, userAgent, true)
	if err != nil {
		return false, nil // probing errors are non-fatal
	}
	if !isChallengePage(page) {
		return false, nil
	}
	if err := solveChallengePage(page, base, userAgent, solver, jar); err != nil {
		return false, err
	}
	return true, nil
}

func solveChallengePage(page, base, userAgent string, solver *http.Client, jar *controlplane.CookieJar) error {
	prefixMatch := challengePrefixRe.FindString(page)
	if prefixMatch == "" {
		return &Error{Msg: "challenge asset prefix not found on " + base}
	}
	prefixURL := base + prefixMatch

	script, err := fetchText(solver, prefixURL+"/script.js?reload=true", htmlAccept, userAgent, false)
	if err != nil {
		return err
	}
	challenges, token, err := parseChallengeInit(script, prefixMatch)
	if err != nil {
		return err
	}

	for round := 0; round < maxPostBackRounds; round++ {
		answers := make([]map[string]any, 0, len(challenges))
		for _, ch := range challenges {
			ans, err := answerChallenge(solver, prefixURL, token, ch, userAgent)
			if err != nil {
				return err
			}
			answers = append(answers, ans)
		}
		postBody, _ := json.Marshal(map[string]any{"token": token, "data": answers})
		req, err := http.NewRequest("POST", prefixURL+"/fst-post-back", bytes.NewReader(postBody))
		if err != nil {
			return err
		}
		for k, v := range remoteconfig.SolverHeaders() {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Origin", baseOrigin(prefixURL))
		resp, err := solver.Do(req)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &Error{Msg: fmt.Sprintf("challenge post-back returned HTTP %d", resp.StatusCode)}
		}
		var result struct {
			Status string `json:"status"`
			Ch     []map[string]any `json:"ch"`
			Tok    string `json:"tok"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return &Error{Msg: "unexpected challenge post-back response"}
		}
		if result.Status == "success" {
			verification, err := fetchText(solver, base+"/", htmlAccept, userAgent, true)
			if err != nil {
				return err
			}
			if isChallengePage(verification) {
				return &Error{Msg: "challenge cookie not accepted on this exit IP"}
			}
			if err := installChallengeCookies(jar); err != nil {
				return err
			}
			logx.Info(tag, "challenge solved and cookies installed")
			return nil
		}
		if len(result.Ch) == 0 || result.Tok == "" {
			return &Error{Msg: "unexpected challenge post-back response"}
		}
		challenges = result.Ch
		token = result.Tok
	}
	return &Error{Msg: fmt.Sprintf("Fastly challenge did not complete within %d rounds", maxPostBackRounds)}
}
