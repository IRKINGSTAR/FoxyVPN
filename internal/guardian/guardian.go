// Guardian API client: proxy pass issuance, entitlement and quota.
package guardian

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"foxyvpn/internal/controlplane"
	"foxyvpn/internal/fastly"
	"foxyvpn/internal/logx"
	"foxyvpn/internal/model"
	"foxyvpn/internal/remoteconfig"
)

const tag = "Guardian"

const DefaultEndpoint = "https://vpn.mozilla.org"

// HTTPError carries status code and optional Retry-After.
type HTTPError struct {
	Message     string
	StatusCode  int
	RetryAfterMs *int64
}

func (e *HTTPError) Error() string { return e.Message }

// QuotaExceeded signals an exhausted account quota (HTTP 429).
type QuotaExceeded struct {
	QuotaMax       *int64
	QuotaRemaining *int64
	QuotaReset     *int64
}

func (e *QuotaExceeded) Error() string { return "account proxy quota exceeded" }

// TokenInvalid signals the OAuth token was rejected.
type TokenInvalid struct{ Msg string }

func (e *TokenInvalid) Error() string { return e.Msg }

// ProxyPass as returned by /fpn/token.
type ProxyPass struct {
	Token                string `json:"-"`
	ExpiresAtEpochSeconds *int64 `json:"-"`
	QuotaMax             *int64
	QuotaRemaining       *int64
	QuotaReset           *int64
}

func (p ProxyPass) String() string {
	if p.ExpiresAtEpochSeconds == nil {
		return "ProxyPass(lifetime not stated)"
	}
	return fmt.Sprintf("ProxyPass(expiresAtEpochSeconds=%d)", *p.ExpiresAtEpochSeconds)
}

type Client struct {
	client *http.Client
	jar    *controlplane.CookieJar
}

func New() *Client {
	return &Client{client: controlplane.Client(), jar: controlplane.Jar}
}

func guardianUserAgent() string {
	if ua, ok := remoteconfig.GuardianHeaders()["User-Agent"]; ok {
		return ua
	}
	return remoteconfig.ControlPlaneUserAgent()
}

func headerLong(h *http.Header, names ...string) *int64 {
	for _, n := range names {
		v := strings.TrimSpace(h.Get(n))
		if v == "" {
			continue
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return &n
		}
	}
	return nil
}

func retryAfterMs(h *http.Header) *int64 {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return nil
	}
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if seconds > (1<<62)/1000 {
			return nil
		}
		ms := seconds * 1000
		return &ms
	}
	if t, err := http.ParseTime(raw); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		ms := d.Milliseconds()
		return &ms
	}
	return nil
}

// FetchProxyPass gets a fresh proxy pass JWT.
func (c *Client) FetchProxyPass(endpoint, accessToken string) (ProxyPass, error) {
	u := strings.TrimSuffix(endpoint, "/") + "/api/v1/fpn/token"
	resp, err := c.authorizedRequest("GET", u, accessToken)
	if err != nil {
		return ProxyPass{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 401, 403:
		return ProxyPass{}, &TokenInvalid{Msg: "access token was rejected by Guardian"}
	case 429:
		remaining := headerLong(&resp.Header, "X-Quota-Remaining", "Quota-Remaining")
		if remaining != nil && *remaining <= 0 {
			return ProxyPass{}, &QuotaExceeded{
				QuotaMax:       headerLong(&resp.Header, "X-Quota-Limit", "Quota-Limit"),
				QuotaRemaining: int64Ptr(0),
				QuotaReset:     headerLong(&resp.Header, "X-Quota-Reset", "Quota-Reset"),
			}
		}
		return ProxyPass{}, &HTTPError{
			Message:      "Guardian rate limited the request; retry later",
			StatusCode:   429,
			RetryAfterMs: retryAfterMs(&resp.Header),
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode != 200 {
		return ProxyPass{}, &HTTPError{
			Message:      fmt.Sprintf("failed to fetch proxy pass: HTTP %d", resp.StatusCode),
			StatusCode:   resp.StatusCode,
			RetryAfterMs: retryAfterMs(&resp.Header),
		}
	}
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || strings.TrimSpace(parsed.Token) == "" {
		return ProxyPass{}, &HTTPError{Message: "proxy pass response did not contain a valid token"}
	}
	expiresAt := jwtExpiryEpochSeconds(parsed.Token)
	return ProxyPass{
		Token:                parsed.Token,
		ExpiresAtEpochSeconds: expiresAt,
		QuotaMax:             headerLong(&resp.Header, "X-Quota-Limit", "Quota-Limit"),
		QuotaRemaining:       headerLong(&resp.Header, "X-Quota-Remaining", "Quota-Remaining"),
		QuotaReset:           headerLong(&resp.Header, "X-Quota-Reset", "Quota-Reset"),
	}, nil
}

// FetchUserInfo combines the pass and status endpoints.
func (c *Client) FetchUserInfo(endpoint, accessToken string) (model.Entitlement, error) {
	var pass *ProxyPass
	var quotaExceeded *QuotaExceeded
	var passFailure error
	p, err := c.FetchProxyPass(endpoint, accessToken)
	if err == nil {
		pass = &p
	} else {
		var ti *TokenInvalid
		var qe *QuotaExceeded
		if errors.As(err, &ti) {
			_, _ = c.ActivateGuardian(endpoint, accessToken)
			var p2 ProxyPass
			p2, err2 := c.FetchProxyPass(endpoint, accessToken)
			if err2 == nil {
				pass = &p2
			}
		} else if errors.As(err, &qe) {
			quotaExceeded = qe
		} else {
			passFailure = err
			logx.WarnErr(tag, err)
		}
	}

	statusURL := strings.TrimSuffix(endpoint, "/") + "/api/v1/fpn/status"
	var statusEntitlement *model.Entitlement
	if resp, err := c.authorizedRequest("GET", statusURL, accessToken); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			var obj map[string]any
			if json.Unmarshal(body, &obj) == nil {
				e := parseEntitlement(obj)
				statusEntitlement = &e
			}
		}
	}

	if pass == nil && quotaExceeded == nil && statusEntitlement == nil {
		if passFailure != nil {
			return model.Entitlement{}, passFailure
		}
		return model.Entitlement{}, &HTTPError{Message: "could not obtain entitlement from Guardian"}
	}

	var remaining, maxBytes *int64
	if pass != nil {
		remaining = pass.QuotaRemaining
		maxBytes = pass.QuotaMax
	} else if quotaExceeded != nil {
		remaining = quotaExceeded.QuotaRemaining
		maxBytes = quotaExceeded.QuotaMax
	} else if statusEntitlement != nil {
		remaining = statusEntitlement.QuotaRemaining
		maxBytes = statusEntitlement.MaxBytes
	}

	limited := true
	if remaining == nil && maxBytes == nil && statusEntitlement != nil {
		limited = statusEntitlement.LimitedBandwidth
	} else if remaining != nil || maxBytes != nil {
		limited = true
	}
	return model.Entitlement{MaxBytes: maxBytes, LimitedBandwidth: limited, QuotaRemaining: remaining}, nil
}

// ActivateGuardian enables the Guardian entitlement.
func (c *Client) ActivateGuardian(endpoint, accessToken string) (model.Entitlement, error) {
	u := strings.TrimSuffix(endpoint, "/") + "/api/v1/fpn/activate"
	resp, err := c.authorizedRequest("POST", u, accessToken)
	if err != nil {
		return model.Entitlement{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode != 200 {
		return model.Entitlement{}, &HTTPError{
			Message:      fmt.Sprintf("failed to activate guardian entitlement: HTTP %d", resp.StatusCode),
			StatusCode:   resp.StatusCode,
			RetryAfterMs: retryAfterMs(&resp.Header),
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return model.Entitlement{}, err
	}
	return parseEntitlement(obj), nil
}

func parseEntitlement(body map[string]any) model.Entitlement {
	longFrom := func(keys ...string) *int64 {
		for _, k := range keys {
			v, ok := body[k]
			if !ok || v == nil {
				continue
			}
			if f, ok := v.(float64); ok && f >= 0 {
				n := int64(f)
				return &n
			}
		}
		return nil
	}
	max := longFrom("maxBytes", "max_bytes", "quota_limit")
	remaining := longFrom("quota_remaining", "quotaRemaining")
	limitedDefault := max != nil || remaining != nil
	limited, _ := body["limited_bandwidth"].(bool)
	if limitedAny, ok := body["limitedBandwidth"].(bool); ok {
		limited = limitedAny
	}
	if !limited && !limitedDefault {
		limited = limitedDefault
	}
	if _, exists := body["limited_bandwidth"]; exists {
		limited, _ = body["limited_bandwidth"].(bool)
	} else if _, exists := body["limitedBandwidth"]; exists {
		limited, _ = body["limitedBandwidth"].(bool)
	} else {
		limited = limitedDefault
	}
	return model.Entitlement{MaxBytes: max, LimitedBandwidth: limited, QuotaRemaining: remaining}
}

func (c *Client) authorizedRequest(method, rawURL, accessToken string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Hostname()

	buildRequest := func() (*http.Request, error) {
		var body io.Reader
		if method == "POST" {
			body = bytes.NewReader(nil)
		}
		req, err := http.NewRequest(method, rawURL, body)
		if err != nil {
			return nil, err
		}
		for k, v := range remoteconfig.GuardianHeaders() {
			if strings.EqualFold(k, "User-Agent") {
				req.Header.Set(k, v)
			} else if !strings.EqualFold(k, "Content-Length") && !strings.EqualFold(k, "Host") {
				req.Header.Set(k, v)
			}
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return req, nil
	}

	attempts := 1
	req, err := buildRequest()
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	for resp.StatusCode == 406 && attempts < 5 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
		resp.Body.Close()
		solveErr := fastly.SolveAndInstall(string(body), origin, guardianUserAgent())
		if solveErr != nil {
			logx.WarnErr(tag, fmt.Errorf("could not solve the Fastly challenge: %w", solveErr))
			return nil, &HTTPError{
				Message: "Mozilla's bot protection rejected this request (HTTP 406) and the challenge " +
					"could not be solved automatically. Try again later or on another network.",
				StatusCode: 406,
			}
		}
		req, _ = buildRequest()
		resp, err = c.client.Do(req)
		if err != nil {
			return nil, err
		}
		attempts++
	}
	if resp.StatusCode == 406 {
		// let the caller trigger a remote-config refresh as in Kotlin
	}
	return resp, nil
}

func int64Ptr(v int64) *int64 { return &v }

// JWTExpiryEpochSeconds parses exp from the proxy pass JWT.
func JWTExpiryEpochSeconds(token string) *int64 { return jwtExpiryEpochSeconds(token) }

func jwtExpiryEpochSeconds(token string) *int64 {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	payload := parts[1]
	if b, err := base64.RawURLEncoding.DecodeString(payload); err == nil {
		var claims struct {
			Exp int64 `json:"exp"`
		}
		if json.Unmarshal(b, &claims) == nil && claims.Exp > 0 {
			return &claims.Exp
		}
	}
	// tolerate padded input
	if b, err := base64.URLEncoding.DecodeString(payload + strings.Repeat("=", (4-len(payload)%4)%4)); err == nil {
		var claims struct {
			Exp int64 `json:"exp"`
		}
		if json.Unmarshal(b, &claims) == nil && claims.Exp > 0 {
			return &claims.Exp
		}
	}
	return nil
}
