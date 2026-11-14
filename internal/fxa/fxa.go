// Firefox Accounts auth: session token to OAuth exchange (HAWK, PKCE),
// token refresh, and Fastly 406 handling.
package fxa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
	"foxyvpn/internal/fastly"
	"foxyvpn/internal/logx"
	"foxyvpn/internal/model"
	"foxyvpn/internal/remoteconfig"
	"foxyvpn/internal/storage"
)

const tag = "Fxa"

const (
	fxaAuthServer   = "https://api.accounts.firefox.com/v1"
	fxaOAuthServer  = "https://oauth.accounts.firefox.com/v1"
	firefoxClientID = "5882386c6d801776"
	oauthScope      = "profile https://identity.mozilla.com/apps/vpn"
	protocolVersion = "identity.mozilla.com/picl/v1/"

	maxChallengeAttempts  = 5
	defaultAccessTokenTTL = 24 * 60 * 60
	maxConfirmAttempts    = 100
	confirmPollDelay      = 3 * time.Second

	webchannelLoginURL = "https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email"
)

const friendly406 = "Mozilla's bot protection rejected this request (HTTP 406) and the automatic " +
	"challenge could not be completed on this network. Please switch networks and try again."

var sessionTokenHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// APIError is a structured FxA error.
type APIError struct {
	Message    string
	Errno      *int
	StatusCode int
}

func (e *APIError) Error() string { return e.Message }

func (e *APIError) IsUnconfirmedSession() bool {
	if e.Errno != nil && (*e.Errno == 104 || *e.Errno == 138) {
		return true
	}
	if (e.StatusCode == 400 || e.StatusCode == 401) &&
		(strings.Contains(strings.ToLower(e.Message), "unconfirmed") ||
			strings.Contains(strings.ToLower(e.Message), "unverified")) {
		return true
	}
	return false
}

// RefreshFailure is returned when the stored session could not be renewed.
type RefreshFailure struct {
	Message   string
	Permanent bool
	Cause     error
}

func (e *RefreshFailure) Error() string { return e.Message }
func (e *RefreshFailure) Unwrap() error { return e.Cause }

// BlockedError is returned when Fastly blocks us and the challenge failed.
type BlockedError struct{ Msg string }

func (e *BlockedError) Error() string { return e.Msg }

func cleanToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '"' {
			return -1
		}
		return r
	}, s)
	return strings.ToLower(s)
}

// Repository manages the FxA session and OAuth tokens.
type Repository struct {
	tokens      *storage.TokenStore
	loginMu     sync.Mutex
	refreshMu   sync.Mutex
	client      *http.Client
	jar         *controlplane.CookieJar
	invalidator func(newEpoch int64)
}

func NewRepository(tokens *storage.TokenStore) *Repository {
	return &Repository{
		tokens: tokens,
		client: controlplane.NoRedirectClient(),
		jar:    controlplane.Jar,
	}
}

func (r *Repository) BrowserLoginURL() string { return webchannelLoginURL }

// CleanSessionToken validates and normalizes a candidate session token.
func CleanSessionToken(s string) (string, bool) {
	c := cleanToken(s)
	if !sessionTokenHexRe.MatchString(c) {
		return "", false
	}
	return c, true
}

// ---- HAWK ----

func hkdf(ikm []byte, info string, length int) []byte {
	salt := make([]byte, 32)
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	infoBytes := []byte(info)
	var result []byte
	var previous []byte
	counter := byte(1)
	for len(result) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(previous)
		mac.Write(infoBytes)
		mac.Write([]byte{counter})
		block := mac.Sum(nil)
		take := length - len(result)
		if take > len(block) {
			take = len(block)
		}
		result = append(result, block[:take]...)
		previous = block
		counter++
	}
	return result
}

func deriveHawkCredentials(sessionTokenHex string) (string, []byte) {
	token, _ := hex.DecodeString(sessionTokenHex)
	expanded := hkdf(token, protocolVersion+"sessionToken", 64)
	return hex.EncodeToString(expanded[:32]), expanded[32:64]
}

func hawkHeader(method string, rawURL *url.URL, tokenID string, hmacKey []byte, body []byte) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonceBytes := make([]byte, 6)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	path := rawURL.EscapedPath()
	if rawURL.RawQuery != "" {
		path += "?" + rawURL.RawQuery
	}
	payloadHash := ""
	if len(body) > 0 {
		digest := sha256.New()
		digest.Write([]byte("hawk.1.payload\napplication/json\n"))
		digest.Write(body)
		digest.Write([]byte("\n"))
		payloadHash = base64.StdEncoding.EncodeToString(digest.Sum(nil))
	}
	port := rawURL.Port()
	if port == "" {
		if rawURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	normalized := fmt.Sprintf("hawk.1.header\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n",
		ts, nonce, strings.ToUpper(method), path, rawURL.Hostname(), port, payloadHash)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(normalized))
	macB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	header := fmt.Sprintf("Hawk id=\"%s\", ts=\"%s\", nonce=\"%s\", mac=\"%s\"", tokenID, ts, nonce, macB64)
	if payloadHash != "" {
		header += fmt.Sprintf(", hash=\"%s\"", payloadHash)
	}
	return header
}

func applyFirefoxHeaders(req *http.Request) {
	for k, v := range remoteconfig.ControlPlaneHeaders() {
		if strings.EqualFold(k, "User-Agent") {
			req.Header.Set(k, v)
		} else if !strings.EqualFold(k, "Accept-Encoding") && !strings.EqualFold(k, "Content-Length") && !strings.EqualFold(k, "Host") {
			req.Header.Set(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", remoteconfig.ControlPlaneUserAgent())
	}
}

// ---- session verification ----

// IsSessionVerified checks the recovery email status via HAWK.
func (r *Repository) IsSessionVerified(sessionToken string) bool {
	clean := cleanToken(sessionToken)
	if !sessionTokenHexRe.MatchString(clean) {
		return false
	}
	u, _ := url.Parse(fxaAuthServer + "/recovery_email/status")
	tokenID, hmacKey := deriveHawkCredentials(clean)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return false
	}
	applyFirefoxHeaders(req)
	req.Header.Set("Authorization", hawkHeader("GET", u, tokenID, hmacKey, nil))
	resp, err := r.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		return false
	}
	var status struct {
		Verified bool `json:"verified"`
	}
	if json.Unmarshal(body, &status) != nil {
		return false
	}
	return status.Verified
}

// ---- login completion ----

// CompleteBrowserLogin exchanges a captured WebChannel session token for
// OAuth tokens and stores them. Returns error on failure.
func (r *Repository) CompleteBrowserLogin(sessionToken string) error {
	r.loginMu.Lock()
	defer r.loginMu.Unlock()
	clean := cleanToken(sessionToken)
	if !sessionTokenHexRe.MatchString(clean) {
		return fmt.Errorf("the sign-in page did not hand over a usable session token")
	}
	epoch := r.tokens.SessionEpoch()
	remoteconfig.Refresh(controlplane.Client())
	return r.completeLogin(clean, epoch)
}

// CompleteLoginWithTokens stores externally obtained tokens (rarely used path).
func (r *Repository) CompleteLoginWithTokens(accessToken, refreshToken string, expiresInSeconds int64) error {
	r.loginMu.Lock()
	defer r.loginMu.Unlock()
	epoch := r.tokens.SessionEpoch()
	if expiresInSeconds <= 0 {
		expiresInSeconds = int64(defaultAccessTokenTTL)
	}
	return r.tokens.CompleteLoginIfCurrent(model.RuntimeAuth{
		AccessToken:         strings.TrimSpace(accessToken),
		RefreshToken:        strings.TrimSpace(refreshToken),
		ExpiresAtEpochSeconds: time.Now().Unix() + expiresInSeconds,
	}, epoch)
}

func (r *Repository) completeLogin(sessionToken string, epoch int64) error {
	confirmed := false
	for attempt := 0; attempt < maxConfirmAttempts; attempt++ {
		if r.IsSessionVerified(sessionToken) {
			confirmed = true
			break
		}
		select {
		case <-time.After(confirmPollDelay):
		}
	}
	if !confirmed {
		return &APIError{Message: "Sign-in verification timed out. Please try again.", StatusCode: 408}
	}
	var tokenData map[string]any
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		data, err := r.exchangeSessionWithOAuthCode(sessionToken)
		if err == nil {
			tokenData = data
			break
		}
		lastErr = err
		if apiErr, ok := err.(*APIError); ok && apiErr.IsUnconfirmedSession() && attempt < 9 {
			time.Sleep(confirmPollDelay)
			continue
		}
		return err
	}
	if tokenData == nil {
		return fmt.Errorf("sign-in failed: %w", lastErr)
	}
	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		return fmt.Errorf("Firefox Accounts returned no access token")
	}
	refreshToken, _ := tokenData["refresh_token"].(string)
	if err := r.tokens.CompleteLoginIfCurrent(model.RuntimeAuth{
		AccessToken:         accessToken,
		RefreshToken:        refreshToken,
		ExpiresAtEpochSeconds: expiryFrom(tokenData),
	}, epoch); err != nil {
		return err
	}
	// Best-effort: destroy the FxA session now that tokens are stored.
	r.DestroySession(sessionToken)
	return nil
}

func expiryFrom(tokenData map[string]any) int64 {
	expiresIn := 0
	if v, ok := tokenData["expires_in"].(float64); ok {
		expiresIn = int(v)
	}
	if expiresIn <= 0 {
		expiresIn = defaultAccessTokenTTL
	}
	return time.Now().Unix() + int64(expiresIn)
}

func (r *Repository) exchangeSessionWithOAuthCode(sessionToken string) (map[string]any, error) {
	verifierBytes := make([]byte, 32)
	_, _ = rand.Read(verifierBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeSum := sha256.Sum256([]byte(verifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	authorizeBody := map[string]any{
		"client_id":            firefoxClientID,
		"response_type":        "code",
		"scope":                oauthScope,
		"state":                state,
		"access_type":          "offline",
		"code_challenge":       codeChallenge,
		"code_challenge_method": "S256",
	}
	authResponse, err := r.executeFxaRequest(fxaAuthServer, "/oauth/authorization", authorizeBody, sessionToken)
	if err != nil {
		return nil, err
	}
	code, _ := authResponse["code"].(string)
	returnedState, _ := authResponse["state"].(string)
	if code == "" || subtle.ConstantTimeCompare([]byte(returnedState), []byte(state)) != 1 {
		return nil, &APIError{Message: "Invalid OAuth authorization response", StatusCode: 500}
	}
	tokenBody := map[string]any{
		"client_id":     firefoxClientID,
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": verifier,
	}
	tokens, err := r.executeFxaRequest(fxaOAuthServer, "/token", tokenBody, "")
	if err != nil {
		return nil, err
	}
	if at, _ := tokens["access_token"].(string); at == "" {
		return nil, &APIError{Message: "OAuth token response is missing access token", StatusCode: 500}
	}
	return tokens, nil
}

// executeFxaRequest posts JSON and handles Fastly 406 challenges.
func (r *Repository) executeFxaRequest(baseUrl, path string, jsonBody map[string]any, sessionToken string) (map[string]any, error) {
	u, err := url.Parse(baseUrl + path)
	if err != nil {
		return nil, err
	}
	bodyBytes, _ := json.Marshal(jsonBody)
	origin := u.Scheme + "://" + u.Hostname()

	buildRequest := func() (*http.Request, error) {
		req, err := http.NewRequest("POST", u.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		applyFirefoxHeaders(req)
		req.Header.Set("Content-Type", "application/json")
		if sessionToken != "" {
			tokenID, hmacKey := deriveHawkCredentials(sessionToken)
			req.Header.Set("Authorization", hawkHeader("POST", u, tokenID, hmacKey, bodyBytes))
		}
		return req, nil
	}

	attempts := 1
	req, err := buildRequest()
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	for resp.StatusCode == 406 && attempts < maxChallengeAttempts {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
		resp.Body.Close()
		solveErr := fastly.SolveAndInstall(string(body), origin, remoteconfig.ControlPlaneUserAgent())
		if solveErr != nil {
			logx.WarnErr(tag, fmt.Errorf("could not solve the Fastly challenge: %w", solveErr))
			return nil, &BlockedError{Msg: friendly406}
		}
		req, _ = buildRequest()
		resp, err = r.client.Do(req)
		if err != nil {
			return nil, err
		}
		attempts++
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode >= 400 {
		if resp.StatusCode == 406 {
			return nil, &BlockedError{Msg: friendly406}
		}
		var errBody map[string]any
		_ = json.Unmarshal(body, &errBody)
		msg := ""
		if m, ok := errBody["message"].(string); ok && m != "" {
			msg = m
		} else if m, ok := errBody["error"].(string); ok && m != "" {
			msg = m
		} else if len(bytes.TrimSpace(body)) == 0 {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		} else {
			msg = string(body)
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		apiErr := &APIError{Message: msg, StatusCode: resp.StatusCode}
		if v, ok := errBody["errno"].(float64); ok {
			e := int(v)
			apiErr.Errno = &e
		}
		return nil, apiErr
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid JSON from FxA: %w", err)
	}
	return out, nil
}

// ---- token lifecycle ----

// EnsureFreshAccessToken returns a valid access token, refreshing if needed.
func (r *Repository) EnsureFreshAccessToken(force bool) (model.RuntimeAuth, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	epoch := r.tokens.SessionEpoch()
	current, err := r.tokens.LoadAuth()
	if err != nil {
		return model.RuntimeAuth{}, &RefreshFailure{Message: err.Error(), Permanent: false}
	}
	if current == nil {
		if se := r.tokens.StorageError(); se != "" {
			return model.RuntimeAuth{}, &RefreshFailure{Message: se, Permanent: false}
		}
		return model.RuntimeAuth{}, &RefreshFailure{Message: "Not signed in", Permanent: true}
	}
	if !force && r.tokens.HasValidAccessToken() {
		return *current, nil
	}
	if current.RefreshToken == "" {
		return model.RuntimeAuth{}, &RefreshFailure{Message: "The stored session has no refresh token; sign in again.", Permanent: true}
	}
	body := map[string]any{
		"client_id":     firefoxClientID,
		"grant_type":    "refresh_token",
		"refresh_token": current.RefreshToken,
		"scope":         oauthScope,
	}
	tokenData, err := r.executeFxaRequest(fxaOAuthServer, "/token", body, "")
	if err != nil {
		permanent := false
		if apiErr, ok := err.(*APIError); ok {
			permanent = apiErr.StatusCode == 400 || apiErr.StatusCode == 401 || apiErr.StatusCode == 403 ||
				(apiErr.Errno != nil && *apiErr.Errno == 108)
		}
		return model.RuntimeAuth{}, &RefreshFailure{Message: err.Error(), Permanent: permanent, Cause: err}
	}
	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		return model.RuntimeAuth{}, &RefreshFailure{Message: "FxA returned no access token for the refresh grant", Permanent: false}
	}
	refreshToken := current.RefreshToken
	if rt, _ := tokenData["refresh_token"].(string); rt != "" {
		refreshToken = rt
	}
	renewed := model.RuntimeAuth{
		AccessToken:         accessToken,
		RefreshToken:        refreshToken,
		ExpiresAtEpochSeconds: expiryFrom(tokenData),
	}
	if err := r.tokens.SaveAuthIfCurrent(renewed, epoch); err != nil {
		return model.RuntimeAuth{}, &RefreshFailure{Message: err.Error(), Permanent: false}
	}
	return renewed, nil
}

// CurrentAccessToken returns a token or nil (never fails hard).
func (r *Repository) CurrentAccessToken() (string, bool) {
	auth, err := r.EnsureFreshAccessToken(false)
	if err == nil {
		return auth.AccessToken, true
	}
	if rf, ok := err.(*RefreshFailure); ok && !rf.Permanent && r.tokens.HasValidAccessToken() {
		if a, _ := r.tokens.LoadAuth(); a != nil {
			return a.AccessToken, true
		}
	}
	return "", false
}

// RefreshAccessToken force-refreshes or returns nil.
func (r *Repository) RefreshAccessToken() *model.RuntimeAuth {
	auth, err := r.EnsureFreshAccessToken(true)
	if err != nil {
		logx.WarnErr(tag, fmt.Errorf("access token renewal failed: %w", err))
		return nil
	}
	return &auth
}

// RestoreSession returns ACTIVE, NEEDS_LOGIN or UNREACHABLE.
func (r *Repository) RestoreSession() string {
	epoch := r.tokens.SessionEpoch()
	stored, err := r.tokens.LoadAuth()
	if err != nil || stored == nil {
		return "NEEDS_LOGIN"
	}
	if stored.RefreshToken == "" && !r.tokens.HasValidAccessToken() {
		if r.tokens.ClearIfCurrent(epoch) {
			return "NEEDS_LOGIN"
		}
		if r.tokens.HasValidAccessToken() {
			return "ACTIVE"
		}
		return "UNREACHABLE"
	}
	if r.tokens.HasValidAccessToken() {
		return "ACTIVE"
	}
	if _, err := r.EnsureFreshAccessToken(false); err != nil {
		if rf, ok := err.(*RefreshFailure); ok && rf.Permanent {
			logx.WarnErr(tag, fmt.Errorf("FxA rejected the stored session; signing out: %w", rf))
			if r.tokens.ClearIfCurrent(epoch) {
				return "NEEDS_LOGIN"
			}
			if r.tokens.HasValidAccessToken() {
				return "ACTIVE"
			}
			return "UNREACHABLE"
		}
		logx.WarnErr(tag, fmt.Errorf("could not renew the session right now; staying signed in: %w", err))
		return "UNREACHABLE"
	}
	return "ACTIVE"
}

// DestroySession destroys the FxA session (best effort).
func (r *Repository) DestroySession(sessionToken string) {
	clean := cleanToken(sessionToken)
	if !sessionTokenHexRe.MatchString(clean) {
		return
	}
	u, _ := url.Parse(fxaAuthServer + "/session/destroy")
	tokenID, hmacKey := deriveHawkCredentials(clean)
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader([]byte("{}")))
	if err != nil {
		return
	}
	applyFirefoxHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", hawkHeader("POST", u, tokenID, hmacKey, []byte("{}")))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := r.client.Do(req.WithContext(ctx))
	if err == nil {
		resp.Body.Close()
	}
}

// SignOut clears tokens and cookies.
func (r *Repository) SignOut(clearCookies func()) {
	r.tokens.Clear()
	if clearCookies != nil {
		clearCookies()
	}
}

var _ = logx.Info
