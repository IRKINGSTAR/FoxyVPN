package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"foxyvpn/internal/controlplane"
	"foxyvpn/internal/exitcheck"
	"foxyvpn/internal/fxa"
	"foxyvpn/internal/guardian"
	"foxyvpn/internal/login"
	"foxyvpn/internal/logx"
	"foxyvpn/internal/model"
	"foxyvpn/internal/serverlist"
	"foxyvpn/internal/service"
	"foxyvpn/internal/settings"
	"foxyvpn/internal/storage"
	"foxyvpn/internal/tray"
	"foxyvpn/internal/winutil"
)

const tag = "App"

// App is the Wails-bound application facade.
type App struct {
	ctx    context.Context
	cfg    *settings.Store
	creds  *storage.CredentialsStore
	tokens *storage.TokenStore
	svc    *service.Service
	repo   *fxa.Repository
	servers *serverlist.Client
	tray   *tray.Tray

	quitRequested    bool
	loginMu          sync.Mutex
	loginRunning     bool
	cachedCountries  []model.Country
	countriesMu      sync.Mutex
	snapshotCancel   func()
}

// showWindow brings the main window to the front (tray callback).
func (a *App) showWindow() {
	if a.ctx == nil {
		return
	}
	runtime.WindowShow(a.ctx)
}

// quitFromTray terminates the application (tray callback).
func (a *App) quitFromTray() {
	if a.ctx == nil {
		os.Exit(0)
	}
	a.quitRequested = true
	runtime.Quit(a.ctx)
}

// BeforeClose hides to tray unless a real quit was requested.
func (a *App) BeforeClose(ctx context.Context) bool {
	if a.quitRequested {
		return false // allow close
	}
	runtime.WindowHide(ctx)
	return true
}

func NewApp(cfg *settings.Store, creds *storage.CredentialsStore, tokens *storage.TokenStore, svc *service.Service) *App {
	return &App{
		cfg:     cfg,
		creds:   creds,
		tokens:  tokens,
		svc:     svc,
		repo:    fxa.NewRepository(tokens),
		servers: serverlist.New(),
	}
}

// Startup is called by Wails when the window is ready.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.snapshotCancel = a.svc.Subscribe(func(snap service.Snapshot) {
		runtime.EventsEmit(a.ctx, "snapshot", snap)
	})
	// Second launches signal this instance to surface its window.
	winutil.WatchActivation(func() {
		runtime.WindowUnminimise(a.ctx)
		runtime.WindowShow(a.ctx)
	})
	go controlplane.TriggerRemoteConfigRefresh()
	a.tray.Start(trayIcon)
	// pending elevated tunnel connect?
	if flag := filepath.Join(settings.AppDataDir(), "connect_tunnel.flag"); fileExists(flag) {
		_ = os.Remove(flag)
		go func() {
			time.Sleep(800 * time.Millisecond)
			_ = a.svc.Connect()
		}()
	}
	if a.isLoggedIn() {
		go func() {
			if err := a.RefreshAccount(); err != nil {
				logx.Debug(tag, "startup account refresh failed: %v", err)
			}
			a.loadRegionsAsync()
		}()
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// Shutdown cleans up on exit.
func (a *App) Shutdown(ctx context.Context) {
	if a.snapshotCancel != nil {
		a.snapshotCancel()
	}
	a.svc.Disconnect()
	winutil.ReleaseSingleInstance()
}

// ---- auth ----

type AuthStatus struct {
	LoggedIn     bool   `json:"loggedIn"`
	StorageError string `json:"storageError,omitempty"`
}

func (a *App) GetAuthStatus() AuthStatus {
	auth, err := a.tokens.LoadAuth()
	if err != nil {
		return AuthStatus{StorageError: err.Error()}
	}
	return AuthStatus{LoggedIn: auth != nil}
}

// StartLogin opens the FxA login WebView window. Emits login:success,
// login:error or login:canceled events.
func (a *App) StartLogin() bool {
	a.loginMu.Lock()
	if a.loginRunning {
		a.loginMu.Unlock()
		return false
	}
	a.loginRunning = true
	a.loginMu.Unlock()

	go func() {
		loginDone := false
		defer func() {
			if r := recover(); r != nil {
				logx.Error(tag, "login flow panic: %v", r)
			}
			if !loginDone {
				a.loginMu.Lock()
				a.loginRunning = false
				a.loginMu.Unlock()
			}
		}()

		completed := make(chan error, 1)
		tokenCh := make(chan string, 4)
		var tokenSeen atomic.Bool

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logx.Error(tag, "token exchange panic: %v", r)
					completed <- fmt.Errorf("internal error during sign-in")
				}
			}()
			for token := range tokenCh {
				completed <- a.repo.CompleteBrowserLogin(token)
				return
			}
		}()

		login.Run(login.Options{
			StartURL: a.repo.BrowserLoginURL(),
			OnSessionToken: func(token string) {
				// Called on the login window's UI thread: must stay fast.
				tokenSeen.Store(true)
				select {
				case tokenCh <- token:
				default:
				}
			},
			OnClosed: func() {},
		})

		a.loginMu.Lock()
		a.loginRunning = false
		a.loginMu.Unlock()
		loginDone = true

		if !tokenSeen.Load() {
			// The user closed the window without completing sign-in.
			runtime.EventsEmit(a.ctx, "login:canceled", true)
			return
		}
		// The window auto-closed after capturing the token; the OAuth
		// exchange keeps running in the background (up to ~5 min of
		// verification polling, mirroring the Android timeouts).
		select {
		case err := <-completed:
			if err != nil {
				runtime.EventsEmit(a.ctx, "login:error", err.Error())
			} else {
				runtime.EventsEmit(a.ctx, "login:success", true)
				go func() {
					if err := a.RefreshAccount(); err != nil {
						logx.Debug(tag, "account refresh after login failed: %v", err)
					}
					a.loadRegionsAsync()
				}()
			}
		case <-time.After(6 * time.Minute):
			runtime.EventsEmit(a.ctx, "login:error", "Sign-in timed out. Please try again.")
		}
		runtime.EventsEmit(a.ctx, "auth:changed", a.GetAuthStatus())
	}()
	return true
}

func (a *App) isLoggedIn() bool {
	auth, _ := a.tokens.LoadAuth()
	return auth != nil
}

// SignOut wipes the session.
func (a *App) SignOut() {
	a.svc.Disconnect()
	a.tokens.Clear()
	controlplane.Jar.Clear()
	_ = a.cfg.Update(func(st *settings.Stored) {
		st.CachedRealIP = ""
		st.CachedRealCountry = ""
		st.CachedQuotaRemaining = nil
		st.CachedQuotaMax = nil
		st.CachedIsUnlimited = false
	})
	runtime.EventsEmit(a.ctx, "auth:changed", a.GetAuthStatus())
}

// RefreshAccount fetches entitlement/quota info from Guardian and caches it
// so the Home screen can show usage before and after connecting.
func (a *App) RefreshAccount() error {
	token, ok := a.repo.CurrentAccessToken()
	if !ok {
		return fmt.Errorf("not signed in")
	}
	ent, err := guardian.New().FetchUserInfo(guardian.DefaultEndpoint, token)
	if err != nil {
		return err
	}
	unlimited := ent.QuotaRemaining == nil && ent.MaxBytes == nil && !ent.LimitedBandwidth
	_ = a.cfg.Update(func(st *settings.Stored) {
		st.CachedQuotaRemaining = ent.QuotaRemaining
		st.CachedQuotaMax = ent.MaxBytes
		st.CachedIsUnlimited = unlimited
	})
	runtime.EventsEmit(a.ctx, "account:changed", map[string]any{
		"quotaRemaining": ent.QuotaRemaining,
		"quotaMax":       ent.MaxBytes,
		"unlimited":      unlimited,
	})
	return nil
}

// ---- connection ----

func (a *App) GetSnapshot() service.Snapshot {
	return a.svc.Snapshot()
}

// Connect starts the connection. mode: "tunnel" | "proxy" | "" (as set).
// When tunnel mode is requested without elevation, the app relaunches
// elevated and returns "elevate".
func (a *App) Connect(mode string) string {
	if mode == "tunnel" && !winutil.IsAdmin() {
		// Persist tunnel mode BEFORE relaunching, so the elevated instance
		// auto-connects with the tunnel configuration.
		_ = a.cfg.Update(func(st *settings.Stored) { st.ProxyOnlyMode = false })
		flag := filepath.Join(settings.AppDataDir(), "connect_tunnel.flag")
		_ = os.WriteFile(flag, []byte("1"), 0o600)
		// Release the single-instance mutex BEFORE launching the elevated
		// instance, otherwise it hits the mutex and exits silently.
		winutil.ReleaseSingleInstance()
		ok, err := winutil.SelfElevate()
		if ok && err == nil {
			go func() {
				time.Sleep(150 * time.Millisecond)
				runtime.Quit(a.ctx)
			}()
			return "elevate"
		}
		_ = os.Remove(flag)
		if err != nil {
			return "elevation failed: " + err.Error()
		}
		return "elevation failed"
	}
	switch mode {
	case "proxy":
		_ = a.cfg.Update(func(st *settings.Stored) { st.ProxyOnlyMode = true })
	case "tunnel":
		_ = a.cfg.Update(func(st *settings.Stored) { st.ProxyOnlyMode = false })
	}
	if err := a.svc.Connect(); err != nil {
		return err.Error()
	}
	return ""
}

func (a *App) Disconnect() {
	a.svc.Disconnect()
}

func (a *App) PingNow() {
	a.svc.PingNow()
}

// ---- regions ----

type CityInfo struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type CountryInfo struct {
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Recommended bool       `json:"recommended"`
	Cities      []CityInfo `json:"cities"`
}

func (a *App) GetRegions() ([]CountryInfo, error) {
	countries, err := a.loadCountries()
	if err != nil {
		return nil, err
	}
	return a.regionInfos(countries), nil
}

func (a *App) regionInfos(countries []model.Country) []CountryInfo {
	var out []CountryInfo
	for _, c := range countries {
		ci := CountryInfo{
			Code:        c.Code,
			Name:        c.DisplayName(),
			Recommended: strings.EqualFold(c.Code, model.RecommendedCountryCode),
		}
		for _, city := range c.Cities {
			ci.Cities = append(ci.Cities, CityInfo{
				Code:  city.Code,
				Name:  city.Name,
				Count: len(city.Servers),
			})
		}
		out = append(out, ci)
	}
	return out
}

// loadRegionsAsync refreshes the directory in the background and pushes it
// to the UI (used on startup / after login).
func (a *App) loadRegionsAsync() {
	countries, err := a.loadCountries()
	if err != nil {
		return
	}
	runtime.EventsEmit(a.ctx, "regions:loaded", a.regionInfos(countries))
}

func (a *App) loadCountries() ([]model.Country, error) {
	a.countriesMu.Lock()
	defer a.countriesMu.Unlock()
	if len(a.cachedCountries) > 0 && a.servers.HasFreshCache() {
		return a.cachedCountries, nil
	}
	countries, err := a.servers.FetchCountries()
	if err != nil {
		if cached := a.servers.LoadCachedCountries(); len(cached) > 0 {
			a.cachedCountries = cached
			return cached, nil
		}
		return nil, err
	}
	a.cachedCountries = countries
	return countries, nil
}

// SelectRegion stores the chosen region.
func (a *App) SelectRegion(countryCode, cityCode string) error {
	countries, err := a.loadCountries()
	if err != nil {
		return err
	}
	for _, c := range countries {
		if !strings.EqualFold(c.Code, countryCode) {
			continue
		}
		for _, city := range c.Cities {
			if cityCode != "" && !strings.EqualFold(city.Code, cityCode) {
				continue
			}
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}
				host, port, ok := serverlist.DefaultConnectTarget(srv)
				if !ok {
					continue
				}
				region := settings.Region{
					CountryCode: c.Code,
					CountryName: c.DisplayName(),
					CityCode:    city.Code,
					CityName:    city.Name,
					Host:        host,
					Port:        port,
				}
				err := a.cfg.Update(func(st *settings.Stored) {
					st.SelectedRegion = &region
				})
				if err == nil {
					runtime.EventsEmit(a.ctx, "region:changed", region)
				}
				return err
			}
		}
	}
	return fmt.Errorf("region not found")
}

func (a *App) GetSelectedRegion() *settings.Region {
	return a.cfg.Get().SelectedRegion
}

// ---- settings ----

type SettingsPayload struct {
	Settings    settings.Stored `json:"settings"`
	Credentials struct {
		LocalProxyUsername       string `json:"localProxyUsername"`
		LocalProxyPasswordSet    bool   `json:"localProxyPasswordSet"`
		UpstreamProxyType        string `json:"upstreamProxyType"`
		UpstreamProxyHost        string `json:"upstreamProxyHost"`
		UpstreamProxyPort        int    `json:"upstreamProxyPort"`
		UpstreamProxyUsername    string `json:"upstreamProxyUsername"`
		UpstreamProxyPasswordSet bool   `json:"upstreamProxyPasswordSet"`
	} `json:"credentials"`
}

func (a *App) GetSettings() SettingsPayload {
	c := a.creds.Get()
	p := SettingsPayload{Settings: a.cfg.Get()}
	p.Credentials.LocalProxyUsername = c.LocalProxyUsername
	p.Credentials.LocalProxyPasswordSet = c.LocalProxyPassword != ""
	p.Credentials.UpstreamProxyType = c.UpstreamProxyType
	p.Credentials.UpstreamProxyHost = c.UpstreamProxyHost
	p.Credentials.UpstreamProxyPort = c.UpstreamProxyPort
	p.Credentials.UpstreamProxyUsername = c.UpstreamProxyUsername
	p.Credentials.UpstreamProxyPasswordSet = c.UpstreamProxyPassword != ""
	return p
}

type SaveSettingsRequest struct {
	Settings *settings.Stored `json:"settings,omitempty"`
	Credentials *struct {
		LocalProxyUsername    string  `json:"localProxyUsername"`
		LocalProxyPassword    *string `json:"localProxyPassword,omitempty"`
		UpstreamProxyType     string  `json:"upstreamProxyType"`
		UpstreamProxyHost     string  `json:"upstreamProxyHost"`
		UpstreamProxyPort     int     `json:"upstreamProxyPort"`
		UpstreamProxyUsername string  `json:"upstreamProxyUsername"`
		UpstreamProxyPassword *string `json:"upstreamProxyPassword,omitempty"`
	} `json:"credentials,omitempty"`
}

func (a *App) SaveSettings(raw string) error {
	var req SaveSettingsRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return err
	}
	if req.Settings != nil {
		d := *req.Settings
		if d.LatencyProbeURL != "" && !settings.IsValidProbeURL(d.LatencyProbeURL) {
			return fmt.Errorf("latency endpoint must be HTTPS")
		}
		if d.MTU < settings.MinMTU || d.MTU > settings.MaxMTU {
			return fmt.Errorf("MTU must be between %d and %d", settings.MinMTU, settings.MaxMTU)
		}
		if err := a.cfg.Update(func(st *settings.Stored) { *st = d }); err != nil {
			return err
		}
	}
	if req.Credentials != nil {
		c := req.Credentials
		err := a.creds.Save(func(st *storage.Credentials) {
			st.LocalProxyUsername = c.LocalProxyUsername
			if c.LocalProxyPassword != nil {
				st.LocalProxyPassword = *c.LocalProxyPassword
			}
			st.UpstreamProxyType = c.UpstreamProxyType
			st.UpstreamProxyHost = strings.Trim(strings.TrimSpace(c.UpstreamProxyHost), "[]")
			st.UpstreamProxyPort = c.UpstreamProxyPort
			st.UpstreamProxyUsername = c.UpstreamProxyUsername
			if c.UpstreamProxyPassword != nil {
				st.UpstreamProxyPassword = *c.UpstreamProxyPassword
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// GetRunningProcesses lists running process names for split tunneling.
func (a *App) GetRunningProcesses() []string {
	out, err := runTasklist()
	if err != nil {
		return nil
	}
	sort.Strings(out)
	return out
}

// ---- logs ----

func (a *App) GetLogs() []logx.Entry {
	return logx.Entries()
}

func (a *App) ClearLogs() {
	logx.Clear()
	runtime.EventsEmit(a.ctx, "logs:cleared", true)
}

// ---- misc ----

func (a *App) GetVersion() string { return "2.0.3-win.1" }

func (a *App) GetRealIP() map[string]string {
	d := a.cfg.Get()
	return map[string]string{"ip": d.CachedRealIP, "country": d.CachedRealCountry}
}

// RefreshRealIP checks the direct (non-tunneled) IP for the status card.
func (a *App) RefreshRealIP() {
	go func() {
		info, err := exitcheck.FetchDirectIPInfo()
		if err != nil {
			return
		}
		_ = a.cfg.Update(func(st *settings.Stored) {
			st.CachedRealIP = info.IP
			st.CachedRealCountry = info.CountryCode
		})
		runtime.EventsEmit(a.ctx, "realip:changed", map[string]string{
			"ip": info.IP, "country": info.CountryCode,
		})
	}()
}
