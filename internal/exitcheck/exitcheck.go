// Exit-IP verification and latency probes through the local proxy.
package exitcheck

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"foxyvpn/internal/controlplane"
	"foxyvpn/internal/settings"
)

const exitCheckURL = "https://www.cloudflare.com/cdn-cgi/trace"

type IpLocationInfo struct {
	IP         string `json:"ip"`
	CountryCode string `json:"countryCode"`
}

// FetchDirectIPInfo asks Cloudflare through the direct (control-plane) path.
func FetchDirectIPInfo() (IpLocationInfo, error) {
	client := controlplane.Client()
	req, _ := http.NewRequest("GET", exitCheckURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return IpLocationInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return IpLocationInfo{}, fmt.Errorf("direct IP check failed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return IpLocationInfo{}, err
	}
	return parseTrace(string(body))
}

// FetchProxiedIPInfo asks Cloudflare through the local mixed proxy.
func FetchProxiedIPInfo(socksPort int, username, password string, timeout time.Duration) (IpLocationInfo, error) {
	proxyURL := socksProxyURL(socksPort, username, password)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	req, _ := http.NewRequest("GET", exitCheckURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return IpLocationInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return IpLocationInfo{}, fmt.Errorf("proxied exit check failed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return IpLocationInfo{}, err
	}
	return parseTrace(string(body))
}

func socksProxyURL(port int, username, password string) *url.URL {
	raw := fmt.Sprintf("socks5://%s%s@127.0.0.1:%d",
		userinfo(username, password), "", port)
	if username == "" {
		raw = fmt.Sprintf("socks5://127.0.0.1:%d", port)
	}
	u, err := url.Parse(raw)
	if err != nil {
		u, _ = url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	}
	return u
}

func userinfo(username, password string) string {
	if username == "" {
		return ""
	}
	if password == "" {
		return url.QueryEscape(username) + "@"
	}
	return url.QueryEscape(username) + ":" + url.QueryEscape(password) + "@"
}

func parseTrace(body string) (IpLocationInfo, error) {
	var ip, loc string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
		} else if strings.HasPrefix(line, "loc=") {
			loc = strings.TrimPrefix(line, "loc=")
		}
	}
	if !settings.IsValidIpAddress(ip) {
		return IpLocationInfo{}, fmt.Errorf("trace response did not contain a valid IP address")
	}
	loc = strings.ToUpper(loc)
	if len(loc) != 2 {
		loc = ""
	}
	for _, c := range loc {
		if c < 'A' || c > 'Z' {
			loc = ""
			break
		}
	}
	return IpLocationInfo{IP: ip, CountryCode: loc}, nil
}

// MeasureProxyLatencyMs: round trip of a GET through the local proxy.
func MeasureProxyLatencyMs(socksPort int, probeURL, username, password string) (int, bool) {
	if !settings.IsValidProbeURL(probeURL) && !strings.HasPrefix(probeURL, "https://") {
		return 0, false
	}
	proxyURL := socksProxyURL(socksPort, username, password)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	start := time.Now()
	req, err := http.NewRequest("GET", probeURL, nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return int(elapsed), true
}

var _ = controlplane.Sha256Hex
