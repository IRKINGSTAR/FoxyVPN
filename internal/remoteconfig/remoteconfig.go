// Remote header/UA config fetched from the FoxyConfig repo.
package remoteconfig

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"foxyvpn/internal/logx"
	"foxyvpn/internal/settings"
)

const tag = "RemoteConfig"

type ComponentConfig struct {
	Headers   map[string]string `json:"headers"`
	Protocols []string          `json:"protocols,omitempty"`
}

type Config struct {
	Version     int             `json:"version"`
	ControlPlane ComponentConfig `json:"controlPlane"`
	Guardian    ComponentConfig `json:"guardian"`
	Solver      ComponentConfig `json:"solver"`
	Browser     ComponentConfig `json:"browser"`
}

const (
	fileName    = "foxy_config.json"
	primaryURL  = "https://raw.githubusercontent.com/Vauth/FoxyConfig/main/config.json"
	fallbackURL = "https://cdn.jsdelivr.net/gh/Vauth/FoxyConfig@main/config.json"
)

var defaultConfig = Config{
	Version: 1,
	ControlPlane: ComponentConfig{Headers: map[string]string{
		"User-Agent":      "MozillaVPN/2.24.0 (sys:android {android_version})",
		"Accept":          "*/*",
		"Accept-Encoding": "identity",
	}, Protocols: []string{"HTTP_2", "HTTP_1_1"}},
	Guardian: ComponentConfig{Headers: map[string]string{
		"User-Agent":      "MozillaVPN/2.24.0 (sys:android {android_version})",
		"Accept":          "application/json",
		"Accept-Encoding": "identity",
		"Content-Type":    "application/json",
		"Cache-Control":   "max-age=0",
	}},
	Solver: ComponentConfig{Headers: map[string]string{
		"User-Agent":      "MozillaVPN/2.24.0 (sys:android {android_version})",
		"Accept-Encoding": "identity",
	}},
	Browser: ComponentConfig{Headers: map[string]string{
		"User-Agent": "Mozilla/5.0 (Android {android_version}; Mobile; rv:159.0) Gecko/159.0 Firefox/159.0",
	}},
}

const (
	androidRelease = "14"
	androidSDK     = "34"
)

var placeholderRe = regexp.MustCompile(`(?i)\$?\{android_version\}|\$?\{os_version\}|\$?\{android_sdk\}`)

// ResolvePlaceholders fills the UA template variables.
func ResolvePlaceholders(raw string) string {
	return placeholderRe.ReplaceAllStringFunc(raw, func(m string) string {
		lower := strings.ToLower(m)
		if strings.Contains(lower, "sdk") {
			return androidSDK
		}
		return androidRelease
	})
}

var (
	mu       sync.Mutex
	current  = resolvedDefaults()
	lastRaw  string
	lastTry  time.Time
)

func resolvedDefaults() Config {
	c := defaultConfig
	c.ControlPlane = resolveComponent(defaultConfig.ControlPlane)
	c.Guardian = resolveComponent(defaultConfig.Guardian)
	c.Solver = resolveComponent(defaultConfig.Solver)
	c.Browser = resolveComponent(defaultConfig.Browser)
	return c
}

func resolveComponent(in ComponentConfig) ComponentConfig {
	out := ComponentConfig{Protocols: in.Protocols, Headers: map[string]string{}}
	for k, v := range in.Headers {
		out.Headers[k] = ResolvePlaceholders(v)
	}
	return out
}

func Init() {
	path := filepath.Join(settings.AppDataDir(), fileName)
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return
	}
	if cfg, ok := parse(string(raw)); ok {
		mu.Lock()
		current = cfg
		lastRaw = string(raw)
		mu.Unlock()
		logx.Info(tag, "loaded cached remote config (v%d)", cfg.Version)
	}
}

func Current() Config {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// ControlPlaneUserAgent returns the effective control-plane UA.
func ControlPlaneUserAgent() string {
	c := Current()
	if ua, ok := c.ControlPlane.Headers["User-Agent"]; ok {
		return ua
	}
	return ResolvePlaceholders("MozillaVPN/2.24.0 (sys:android {android_version})")
}

// BrowserUserAgent returns the effective browser UA (for the login WebView).
func BrowserUserAgent() string {
	c := Current()
	if ua, ok := c.Browser.Headers["User-Agent"]; ok {
		return ua
	}
	return ResolvePlaceholders("Mozilla/5.0 (Android {android_version}; Mobile; rv:159.0) Gecko/159.0 Firefox/159.0")
}

func SolverHeaders() map[string]string  { return Current().Solver.Headers }
func GuardianHeaders() map[string]string { return Current().Guardian.Headers }
func ControlPlaneHeaders() map[string]string { return Current().ControlPlane.Headers }

// Refresh fetches the remote config. client is used for the request so the
// caller can supply the shared control-plane client.
func Refresh(client *http.Client) {
	mu.Lock()
	if time.Since(lastTry) < 15*time.Minute {
		mu.Unlock()
		return
	}
	lastTry = time.Now()
	mu.Unlock()

	fetched := fetch(client, primaryURL)
	if fetched == "" {
		fetched = fetch(client, fallbackURL)
	}
	if fetched == "" {
		return
	}
	mu.Lock()
	if fetched == lastRaw {
		mu.Unlock()
		return
	}
	cfg, ok := parse(fetched)
	if !ok {
		mu.Unlock()
		return
	}
	lastRaw = fetched
	current = cfg
	mu.Unlock()

	path := filepath.Join(settings.AppDataDir(), fileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fetched), 0o600); err == nil {
		_ = os.Rename(tmp, path)
	}
	logx.Info(tag, "config updated (v%d)", cfg.Version)
}

func fetch(client *http.Client, url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	c := client
	if c == nil {
		c = &http.Client{Timeout: 8 * time.Second}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(8 * time.Second):
		}
	}()
	defer close(done)
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		return text
	}
	return ""
}

func parse(raw string) (Config, bool) {
	var root struct {
		Version     int `json:"version"`
		ControlPlane json.RawMessage `json:"controlPlane"`
		Guardian     json.RawMessage `json:"guardian"`
		Solver       json.RawMessage `json:"solver"`
		Browser      json.RawMessage `json:"browser"`
	}
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return Config{}, false
	}
	cfg := resolvedDefaults()
	cfg.Version = root.Version
	if v, ok := parseComponent(root.ControlPlane, defaultConfig.ControlPlane); ok {
		cfg.ControlPlane = v
	}
	if v, ok := parseComponent(root.Guardian, defaultConfig.Guardian); ok {
		cfg.Guardian = v
	}
	if v, ok := parseComponent(root.Solver, defaultConfig.Solver); ok {
		cfg.Solver = v
	}
	if v, ok := parseComponent(root.Browser, defaultConfig.Browser); ok {
		cfg.Browser = v
	}
	return cfg, true
}

func parseComponent(raw json.RawMessage, def ComponentConfig) (ComponentConfig, bool) {
	if len(raw) == 0 {
		return resolveComponent(def), false
	}
	var obj struct {
		Headers  map[string]string `json:"headers"`
		Settings struct {
			Protocols []string `json:"protocols"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return resolveComponent(def), false
	}
	out := resolveComponent(def)
	if len(obj.Headers) > 0 {
		headers := map[string]string{}
		for k, v := range obj.Headers {
			if strings.TrimSpace(v) != "" {
				headers[k] = ResolvePlaceholders(v)
			}
		}
		if len(headers) > 0 {
			out.Headers = headers
		}
	}
	if len(obj.Settings.Protocols) > 0 {
		var protocols []string
		for _, p := range obj.Settings.Protocols {
			switch strings.ToUpper(strings.TrimSpace(p)) {
			case "HTTP_2", "H2":
				protocols = append(protocols, "HTTP_2")
			case "HTTP_1_1", "HTTP1.1":
				protocols = append(protocols, "HTTP_1_1")
			}
		}
		if len(protocols) > 0 {
			out.Protocols = protocols
		}
	}
	return out, true
}
