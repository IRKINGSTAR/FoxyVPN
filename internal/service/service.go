// Package service is the Windows port of FoxyVpnService.kt: the connection
// state machine that mints Guardian proxy passes, builds the sing-box config,
// runs the core in-process, rotates bearer tokens before expiry, and performs
// bounded automatic recovery.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"foxyvpn/internal/configbuilder"
	"foxyvpn/internal/controlplane"
	"foxyvpn/internal/exitcheck"
	"foxyvpn/internal/fxa"
	"foxyvpn/internal/guardian"
	"foxyvpn/internal/logx"
	"foxyvpn/internal/model"
	"foxyvpn/internal/serverlist"
	"foxyvpn/internal/settings"
	"foxyvpn/internal/storage"
	"foxyvpn/internal/winutil"
)

const tag = "FoxyService"

const (
	serverListFetchTimeout = 15 * time.Second
	proxyPassFetchBudget   = 60 * time.Second
	proxyPassRetry         = 5 * time.Second
	maxCredentialLifetime  = 5 * time.Minute
	maxReconnectAttempts   = 6
)

type VpnLiveStats struct {
	TxRateBytesPerSec int64 `json:"txRate"`
	RxRateBytesPerSec int64 `json:"rxRate"`
	SessionBytes      int64 `json:"sessionBytes"`
}

// Snapshot is what the GUI observes.
type Snapshot struct {
	State          string `json:"state"`
	LastError      string `json:"lastError"`
	StatusLabel    string `json:"statusLabel"`
	ProxyOnly      bool   `json:"proxyOnly"`
	SocksEndpoint  string `json:"socksEndpoint,omitempty"`
	Region         string `json:"region,omitempty"`
	RegionCode     string `json:"regionCode,omitempty"`
	ExitIP         string `json:"exitIp,omitempty"`
	ExitCountry    string `json:"exitCountry,omitempty"`
	PingMs         *int   `json:"pingMs,omitempty"`
	Health         string `json:"health"`
	TxRate         int64  `json:"txRate"`
	RxRate         int64  `json:"rxRate"`
	SessionBytes   int64  `json:"sessionBytes"`
	ConnectedAt    *int64 `json:"connectedAt,omitempty"`
	QuotaRemaining *int64 `json:"quotaRemaining,omitempty"`
	QuotaMax       *int64 `json:"quotaMax,omitempty"`
	Unlimited      bool   `json:"unlimited"`
	Reconnecting   bool   `json:"reconnecting"`
}

type Service struct {
	cfg     *settings.Store
	creds   *storage.CredentialsStore
	tokens  *storage.TokenStore
	repo    *fxa.Repository
	servers *serverlist.Client
	guard   *guardian.Client

	mu               sync.Mutex
	state            model.ConnectionState
	lastError        string
	statusLabel      string
	proxyOnly        bool
	gen              int
	stopping         bool
	instance         *box.Box
	trafficCancel    context.CancelFunc
	renewCancel      context.CancelFunc
	activeCandidate  *model.ProxyCandidate
	health           model.TunnelHealth
	pingMs           *int
	edgeIP           *exitcheck.IpLocationInfo
	stats            VpnLiveStats
	connectedAt      *int64
	reconnecting     bool
	recoveryBudget   recoveryBudget
	controllerSecret string
	bearerToken      string
	sysProxyBackup   *winutil.SystemProxyBackup

	observers []func(Snapshot)
	obsMu     sync.Mutex
}

type recoveryBudget struct {
	attempts []time.Time
	mu       sync.Mutex
}

func (b *recoveryBudget) tryAcquire(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	var kept []time.Time
	for _, t := range b.attempts {
		if now.Sub(t) < 15*time.Minute {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 2 {
		b.attempts = kept
		return false
	}
	kept = append(kept, now)
	b.attempts = kept
	return true
}

var setupOnce sync.Once

func ensureCoreSetup() {
	setupOnce.Do(func() {
		dir := settings.AppDataDir()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			logx.WarnErr(tag, err)
			return
		}
		if err := libbox.Setup(&libbox.SetupOptions{
			BasePath:    dir,
			WorkingPath: dir,
			TempPath:    os.TempDir(),
			LogMaxLines: 5000,
			Debug:       false,
		}); err != nil {
			logx.WarnErr(tag, err)
		}
	})
}

func New(cfg *settings.Store, creds *storage.CredentialsStore, tokens *storage.TokenStore) *Service {
	return &Service{
		cfg:     cfg,
		creds:   creds,
		tokens:  tokens,
		repo:    fxa.NewRepository(tokens),
		servers: serverlist.New(),
		guard:   guardian.New(),
		health:  model.TunnelUnknown,
	}
}

// Subscribe registers a snapshot observer. Returns a cancel function.
func (s *Service) Subscribe(fn func(Snapshot)) (cancel func()) {
	s.obsMu.Lock()
	s.observers = append(s.observers, fn)
	idx := len(s.observers) - 1
	s.obsMu.Unlock()
	return func() {
		s.obsMu.Lock()
		s.observers[idx] = nil
		s.obsMu.Unlock()
	}
}

// goSafe runs fn in a goroutine that converts panics into logged errors —
// an unrecovered panic in any background goroutine kills the whole process
// (and with the GUI subsystem the stack is invisible).
func (s *Service) goSafe(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logx.Error(tag, "%s panic: %v", name, r)
			}
		}()
		fn()
	}()
}

func (s *Service) notify() {
	snap := s.Snapshot()
	s.obsMu.Lock()
	obs := make([]func(Snapshot), len(s.observers))
	copy(obs, s.observers)
	s.obsMu.Unlock()
	for _, fn := range obs {
		if fn == nil {
			continue
		}
		func() {
			defer func() { _ = recover() }()
			fn(snap)
		}()
	}
}

func (s *Service) setStateLabelLocked(label string) {
	s.statusLabel = label
}

func (s *Service) setLastError(err string) {
	s.mu.Lock()
	s.lastError = err
	s.mu.Unlock()
	s.notify()
}

func (s *Service) snapshotLocked() Snapshot {
	d := s.cfg.Get()
	snap := Snapshot{
		State:          s.state.String(),
		LastError:      s.lastError,
		StatusLabel:    s.statusLabel,
		ProxyOnly:      s.proxyOnly,
		Health:         s.health.String(),
		Reconnecting:   s.reconnecting,
		Unlimited:      d.CachedIsUnlimited,
		QuotaRemaining: d.CachedQuotaRemaining,
		QuotaMax:       d.CachedQuotaMax,
	}
	if s.state == model.Connected {
		snap.SocksEndpoint = fmt.Sprintf("%s:%d", d.SocksBindAddress, d.SocksPort)
	}
	if s.activeCandidate != nil {
		snap.Region = s.activeCandidate.DisplayName()
		snap.RegionCode = s.activeCandidate.CountryCode
	}
	if s.edgeIP != nil {
		snap.ExitIP = s.edgeIP.IP
		snap.ExitCountry = s.edgeIP.CountryCode
	}
	snap.PingMs = s.pingMs
	snap.TxRate = s.stats.TxRateBytesPerSec
	snap.RxRate = s.stats.RxRateBytesPerSec
	snap.SessionBytes = s.stats.SessionBytes
	snap.ConnectedAt = s.connectedAt
	return snap
}

func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Service) State() model.ConnectionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func isFatal(err error) bool {
	var ti *guardian.TokenInvalid
	if errors.As(err, &ti) {
		return true
	}
	var qe *guardian.QuotaExceeded
	if errors.As(err, &qe) {
		return true
	}
	var se *storage.StorageError
	if errors.As(err, &se) {
		return true
	}
	var rf *fxa.RefreshFailure
	if errors.As(err, &rf) && rf.Permanent {
		return true
	}
	var he *guardian.HTTPError
	if errors.As(err, &he) && (he.StatusCode == 401 || he.StatusCode == 403) {
		return true
	}
	return false
}

func (s *Service) friendlyError(err error) string {
	var qe *guardian.QuotaExceeded
	if errors.As(err, &qe) {
		return "Your VPN quota is exhausted. Try again later."
	}
	var ti *guardian.TokenInvalid
	if errors.As(err, &ti) {
		return "Your session was rejected. Please sign in again."
	}
	var he *guardian.HTTPError
	if errors.As(err, &he) {
		if he.StatusCode == 401 || he.StatusCode == 403 {
			return "Your session was rejected. Please sign in again."
		}
		if he.Message != "" {
			return he.Message
		}
		return "Guardian is temporarily unavailable"
	}
	var rf *fxa.RefreshFailure
	if errors.As(err, &rf) {
		return rf.Message
	}
	if err != nil {
		return err.Error()
	}
	return "Connection failed"
}

// credentialDeadline ports CredentialDeadline.kt (lifetime capped at 5 min).
func credentialDeadline(expirySeconds *int64, now time.Time) time.Time {
	lifetime := maxCredentialLifetime
	if expirySeconds != nil {
		expiry := time.Unix(*expirySeconds, 0)
		if !expiry.After(now) {
			lifetime = 0
		} else {
			lifetime = expiry.Sub(now) - 30*time.Second
			if lifetime < 0 {
				lifetime = 0
			}
			if lifetime > maxCredentialLifetime {
				lifetime = maxCredentialLifetime
			}
		}
	}
	return now.Add(lifetime)
}

func validateProxyPass(pass guardian.ProxyPass) error {
	if strings.TrimSpace(pass.Token) == "" ||
		strings.Contains(pass.Token, "\r") || strings.Contains(pass.Token, "\n") {
		return fmt.Errorf("Guardian returned an invalid proxy credential")
	}
	if pass.ExpiresAtEpochSeconds != nil && *pass.ExpiresAtEpochSeconds-time.Now().Unix() <= 60 {
		return fmt.Errorf("Guardian returned a proxy credential with insufficient lifetime")
	}
	return nil
}

// PortsAvailable mirrors ListenerAvailability.requireAvailable.
func PortsAvailable(ports ...int) error {
	for _, p := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			return fmt.Errorf("port %d is not available: %w", p, err)
		}
		ln.Close()
	}
	return nil
}

// Connect starts a connection (async) with a bounded backoff retry loop.
func (s *Service) Connect() error {
	s.mu.Lock()
	if s.state != model.Disconnected {
		s.mu.Unlock()
		return fmt.Errorf("already connecting or connected")
	}
	s.stopping = false
	s.state = model.Connecting
	s.lastError = ""
	s.statusLabel = "Connecting…"
	s.reconnecting = false
	s.mu.Unlock()
	s.notify()
	s.goSafe("connectLoop", s.connectLoop)
	return nil
}

func (s *Service) connectLoop() {
	attempt := 0
	for {
		err := s.connectOnce(nil)
		if err == nil {
			return // connected; background jobs running
		}
		if isFatal(err) || attempt >= maxReconnectAttempts {
			s.failConnect(err, false)
			return
		}
		attempt++
		delay := time.Duration(1) << time.Duration(attempt) * time.Second
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		delay += time.Duration(250+rand.Intn(750)) * time.Millisecond
		var he *guardian.HTTPError
		if errors.As(err, &he) && he.RetryAfterMs != nil {
			if hint := time.Duration(*he.RetryAfterMs) * time.Millisecond; hint > delay {
				delay = hint
			}
		}
		logx.Warn(tag, "transient connect failure; retrying in %.0fs", delay.Seconds())
		s.mu.Lock()
		s.reconnecting = true
		s.state = model.Connecting
		s.setStateLabelLocked("Reconnecting…")
		s.mu.Unlock()
		s.notify()
		select {
		case <-time.After(delay):
		}
		s.mu.Lock()
		stopped := s.stopping
		s.mu.Unlock()
		if stopped {
			return
		}
	}
}

// requestDisconnect stops everything.
func (s *Service) requestDisconnect(reason string) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	s.gen++
	s.cancelJobsLocked()
	s.mu.Unlock()
	logx.Info(tag, "disconnect: %s", reason)
	libbox.SetBearerToken("")
	go s.teardown()
}

func (s *Service) cancelJobsLocked() {
	if s.trafficCancel != nil {
		s.trafficCancel()
		s.trafficCancel = nil
	}
	if s.renewCancel != nil {
		s.renewCancel()
		s.renewCancel = nil
	}
}

// Disconnect stops the tunnel/proxy.
func (s *Service) Disconnect() {
	s.requestDisconnect("requested by the user")
}

func (s *Service) teardown() {
	s.mu.Lock()
	inst := s.instance
	s.instance = nil
	backup := s.sysProxyBackup
	s.sysProxyBackup = nil
	s.mu.Unlock()
	if inst != nil {
		_ = inst.Close()
	}
	if backup != nil {
		if err := winutil.RestoreSystemProxy(*backup); err != nil {
			logx.WarnErr(tag, fmt.Errorf("could not restore the system proxy: %w", err))
		} else {
			logx.Info(tag, "system proxy restored")
		}
	}
	controlplane.EnableInterfaceBinding(0, 0)
	s.mu.Lock()
	s.health = model.TunnelUnknown
	s.pingMs = nil
	s.edgeIP = nil
	s.activeCandidate = nil
	s.stats = VpnLiveStats{}
	s.connectedAt = nil
	s.reconnecting = false
	s.proxyOnly = false
	s.state = model.Disconnected
	s.stopping = false
	s.mu.Unlock()
	remoteconfigRefresh()
	s.notify()
}

// failConnect drops to DISCONNECTED with a friendly error.
func (s *Service) failConnect(err error, wasRecovery bool) {
	s.mu.Lock()
	s.state = model.Disconnected
	if wasRecovery {
		s.lastError = "Automatic recovery failed. Reconnect to retry."
	} else {
		s.lastError = s.friendlyError(err)
	}
	s.reconnecting = false
	s.mu.Unlock()
	logx.ErrorErr(tag, err)
	libbox.SetBearerToken("")
	s.teardown()
}

// mintProxyPass ports the nested mintProxyPass() of FoxyVpnService.connect().
func (s *Service) mintProxyPass() (guardian.ProxyPass, error) {
	auth, err := s.repo.EnsureFreshAccessToken(false)
	if err != nil {
		return guardian.ProxyPass{}, err
	}
	pass, err := s.guard.FetchProxyPass(guardian.DefaultEndpoint, auth.AccessToken)
	if err == nil {
		s.saveQuota(pass)
		return pass, nil
	}
	var qe *guardian.QuotaExceeded
	if errors.As(err, &qe) {
		return guardian.ProxyPass{}, err
	}
	var ti *guardian.TokenInvalid
	if !errors.As(err, &ti) {
		return guardian.ProxyPass{}, err
	}
	logx.Warn(tag, "Guardian rejected the OAuth access token; renewing it and retrying")
	renewed := s.repo.RefreshAccessToken()
	if renewed == nil {
		logx.Warn(tag, "token renewal failed; activating Guardian entitlement and retrying")
		if _, actErr := s.guard.ActivateGuardian(guardian.DefaultEndpoint, auth.AccessToken); actErr != nil {
			return guardian.ProxyPass{}, actErr
		}
		pass, err = s.guard.FetchProxyPass(guardian.DefaultEndpoint, auth.AccessToken)
		if err != nil {
			return guardian.ProxyPass{}, err
		}
		s.saveQuota(pass)
		return pass, nil
	}
	pass, err = s.guard.FetchProxyPass(guardian.DefaultEndpoint, renewed.AccessToken)
	if err == nil {
		s.saveQuota(pass)
		return pass, nil
	}
	if !errors.As(err, &ti) {
		return guardian.ProxyPass{}, err
	}
	logx.Warn(tag, "still rejected; activating the Guardian entitlement and retrying")
	if _, actErr := s.guard.ActivateGuardian(guardian.DefaultEndpoint, renewed.AccessToken); actErr != nil {
		return guardian.ProxyPass{}, actErr
	}
	pass, err = s.guard.FetchProxyPass(guardian.DefaultEndpoint, renewed.AccessToken)
	if err != nil {
		return guardian.ProxyPass{}, err
	}
	s.saveQuota(pass)
	return pass, nil
}

func (s *Service) saveQuota(pass guardian.ProxyPass) {
	unlimited := false
	if pass.QuotaRemaining == nil && pass.QuotaMax == nil {
		unlimited = s.cfg.Get().CachedIsUnlimited
		// No quota headers: resolve "unlimited vs unknown" through the
		// entitlement endpoint in the background (paid unlimited accounts
		// return no headers on /fpn/token).
		s.goSafe("quotaProbe", func() {
			token, ok := s.repo.CurrentAccessToken()
			if !ok {
				return
			}
			ent, err := s.guard.FetchUserInfo(guardian.DefaultEndpoint, token)
			if err != nil {
				return
			}
			unlimited := ent.QuotaRemaining == nil && ent.MaxBytes == nil && !ent.LimitedBandwidth
			_ = s.cfg.Update(func(st *settings.Stored) {
				st.CachedQuotaRemaining = ent.QuotaRemaining
				st.CachedQuotaMax = ent.MaxBytes
				st.CachedIsUnlimited = unlimited
			})
			s.notify()
		})
	}
	_ = s.cfg.Update(func(st *settings.Stored) {
		st.CachedIsUnlimited = unlimited
		if pass.QuotaRemaining != nil && *pass.QuotaRemaining >= 0 {
			st.CachedQuotaRemaining = pass.QuotaRemaining
		}
		if pass.QuotaMax != nil && *pass.QuotaMax >= 0 {
			st.CachedQuotaMax = pass.QuotaMax
		}
	})
	// Quota changes arrive on renewals (~every 5 min) — surface them to
	// the GUI or the usage bar stays frozen for the whole session.
	s.notify()
}

// resolveCandidate ports resolveConnectCandidate: region selection.
func (s *Service) resolveCandidate() (model.ProxyCandidate, error) {
	d := s.cfg.Get()
	var saved *model.ProxyCandidate
	if d.SelectedRegion != nil {
		saved = &model.ProxyCandidate{
			Host:        d.SelectedRegion.Host,
			Port:        d.SelectedRegion.Port,
			CountryCode: d.SelectedRegion.CountryCode,
			CountryName: d.SelectedRegion.CountryName,
			CityCode:    d.SelectedRegion.CityCode,
		}
	}
	var countries []model.Country
	cached := s.servers.LoadCachedCountries()
	if s.servers.HasFreshCache() && len(cached) > 0 {
		countries = cached
	} else {
		fetched, fetchErr := fetchWithTimeout(s.servers, serverListFetchTimeout)
		if fetchErr != nil {
			logx.WarnErr(tag, fmt.Errorf("could not refresh server directory; using cached selection: %w", fetchErr))
		}
		if len(fetched) > 0 {
			countries = fetched
		} else {
			countries = cached
		}
	}
	if len(countries) == 0 && saved != nil {
		return *saved, nil
	}
	var candidates []model.ProxyCandidate
	for _, c := range countries {
		candidates = append(candidates, serverlist.CandidatesForCountry(countries, c.Code)...)
	}
	pool := serverlist.PreferredConnectionCandidates(candidates, saved)
	if len(pool) == 0 {
		if saved == nil {
			return model.ProxyCandidate{}, errors.New("no servers are available. Choose a location first.")
		}
		return model.ProxyCandidate{}, errors.New("no available servers in the selected location. Choose another location.")
	}
	chosen := pool[rand.Intn(len(pool))]
	_ = s.cfg.Update(func(st *settings.Stored) {
		if st.SelectedRegion == nil {
			st.SelectedRegion = &settings.Region{
				CountryCode: chosen.CountryCode,
				CountryName: chosen.CountryName,
				CityCode:    chosen.CityCode,
				Host:        chosen.Host,
				Port:        chosen.Port,
			}
		}
	})
	return chosen, nil
}

func fetchWithTimeout(c *serverlist.Client, timeout time.Duration) ([]model.Country, error) {
	type result struct {
		countries []model.Country
		err       error
	}
	ch := make(chan result, 1)
	go func() {
		cs, err := c.FetchCountries()
		ch <- result{cs, err}
	}()
	select {
	case r := <-ch:
		return r.countries, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("server directory fetch timed out")
	}
}

func (s *Service) currentSettings() (settings.Stored, storage.Credentials) {
	return s.cfg.Get(), s.creds.Get()
}

func proxyCreds(c storage.Credentials) settings.ProxyCredentials {
	return settings.ProxyCredentials{
		LocalProxyUsername:    c.LocalProxyUsername,
		LocalProxyPassword:    c.LocalProxyPassword,
		UpstreamProxyType:     settings.UpstreamProxyType(c.UpstreamProxyType),
		UpstreamProxyHost:     c.UpstreamProxyHost,
		UpstreamProxyPort:     c.UpstreamProxyPort,
		UpstreamProxyUsername: c.UpstreamProxyUsername,
		UpstreamProxyPassword: c.UpstreamProxyPassword,
	}
}

func ownProcessName() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return strings.ToLower(filepath.Base(exe))
}

// startBoxInstance parses config and starts the core.
func (s *Service) startBoxInstance(configContent string) (*box.Box, error) {
	ctx := box.Context(context.Background(),
		include.InboundRegistry(),
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
		include.CertificateProviderRegistry(),
	)
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, []byte(configContent))
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	instance, err := box.New(box.Options{
		Context:           ctx,
		Options:           options,
		PlatformLogWriter: platformLogger{},
	})
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return instance, nil
}

type platformLogger struct{}

func (platformLogger) WriteMessage(level log.Level, message string) {
	switch level {
	case log.LevelPanic, log.LevelFatal, log.LevelError:
		logx.Error("core", "%s", message)
	case log.LevelWarn:
		logx.Warn("core", "%s", message)
	case log.LevelInfo:
		logx.Info("core", "%s", message)
	default:
		logx.Debug("core", "%s", message)
	}
}

// connectOnce performs one full connection attempt. candidate==nil means
// "resolve a candidate from the directory". Returns nil once CONNECTED.
func (s *Service) connectOnce(candidate *model.ProxyCandidate) error {
	ensureCoreSetup()

	s.mu.Lock()
	gen := s.gen
	stopping := s.stopping
	s.mu.Unlock()
	if stopping {
		return errors.New("service is stopping")
	}

	auth, err := s.tokens.LoadAuth()
	if err != nil {
		return fmt.Errorf("credential storage error: %w", err)
	}
	if auth == nil {
		if se := s.tokens.StorageError(); se != "" {
			return fmt.Errorf("credential storage error: %s", se)
		}
		return errors.New("not signed in")
	}

	d, creds := s.currentSettings()
	if err := s.cfg.ValidateForConnect(d, proxyCreds(creds)); err != nil {
		return err
	}
	if err := PortsAvailable(d.SocksPort, settings.ControllerPort); err != nil {
		return err
	}

	if candidate == nil {
		c, err := s.resolveCandidate()
		if err != nil {
			return err
		}
		candidate = &c
	}

	pass, err := s.mintProxyPass()
	if err != nil {
		return err
	}
	if err := validateProxyPass(pass); err != nil {
		return err
	}
	deadline := credentialDeadline(pass.ExpiresAtEpochSeconds, time.Now())
	lifetime := time.Until(deadline)
	note := " (lifetime not stated)"
	if pass.ExpiresAtEpochSeconds != nil {
		note = fmt.Sprintf(" (valid for %ds)", int(lifetime.Seconds()))
	}
	logx.Info(tag, "acquired Guardian proxy pass%s", note)

	s.controllerSecret = storage.RandomHex(16)
	configContent, err := configbuilder.Build(s.buildInstanceInput(d, creds, *candidate, pass.Token))
	if err != nil {
		return err
	}
	// The fork requires the bearer token to be installed in the global
	// registry before the config is parsed (mirrors Libbox.setBearerToken
	// before startOrReloadService on Android).
	libbox.SetBearerToken(pass.Token)
	if err := libbox.CheckConfig(configContent); err != nil {
		libbox.SetBearerToken("")
		return fmt.Errorf("invalid VPN configuration: %w", err)
	}
	logx.Debug(tag, "sing-box config validated successfully")

	inst, err := s.startBoxInstance(configContent)
	if err != nil {
		return fmt.Errorf("could not start the core: %w", err)
	}

	s.mu.Lock()
	if s.gen != gen || s.stopping {
		s.mu.Unlock()
		_ = inst.Close()
		return errors.New("connect was superseded")
	}
	s.instance = inst
	s.bearerToken = pass.Token
	s.activeCandidate = candidate
	s.proxyOnly = d.ProxyOnlyMode
	s.health = model.TunnelChecking
	s.pingMs = nil
	s.edgeIP = nil
	now := time.Now().Unix()
	s.connectedAt = &now
	s.reconnecting = false
	s.state = model.Connected
	s.statusLabel = connectedLabel(d, *candidate)
	s.mu.Unlock()

	logx.Info(tag, "CONNECTED via sing-box core to %s", candidate.Authority())
	s.notify()

	// Proxy-only mode: optionally point the Windows system proxy at the
	// local listener so browsers follow without manual configuration.
	// (Only when not already applied — recovery reconnects must not treat
	// our own proxy as the previous configuration.)
	if d.ProxyOnlyMode && d.EffectiveSystemProxy() {
		s.mu.Lock()
		alreadyApplied := s.sysProxyBackup != nil
		s.mu.Unlock()
		if !alreadyApplied {
			backup := winutil.ReadSystemProxy()
			server := fmt.Sprintf("127.0.0.1:%d", d.SocksPort)
			if err := winutil.ApplySystemProxy(server); err != nil {
				logx.WarnErr(tag, fmt.Errorf("could not apply the system proxy: %w", err))
			} else {
				s.mu.Lock()
				s.sysProxyBackup = &backup
				s.mu.Unlock()
				logx.Info(tag, "system proxy set to %s", server)
			}
		}
	}

	applyInterfaceBinding(d.ProxyOnlyMode)

	s.startTrafficReader(gen)
	s.startCredentialRenewal(gen, deadline)
	s.startHealthMonitor(gen)
	s.startExitCheck(gen, d, creds)
	return nil
}

func applyInterfaceBinding(proxyOnly bool) {
	controlplane.EnableInterfaceBinding(0, 0)
	if !proxyOnly {
		if v4, v6 := controlplane.DefaultInterfaceIndices(); v4 != 0 || v6 != 0 {
			controlplane.EnableInterfaceBinding(v4, v6)
		}
	}
}

func connectedLabel(d settings.Stored, candidate model.ProxyCandidate) string {
	if d.ProxyOnlyMode {
		return fmt.Sprintf("Proxy active • %s:%d", d.SocksBindAddress, d.SocksPort)
	}
	return fmt.Sprintf("Connected • %s", candidate.DisplayName())
}

// buildInstanceInput assembles the configbuilder input.
func (s *Service) buildInstanceInput(d settings.Stored, c storage.Credentials, candidate model.ProxyCandidate, bearer string) configbuilder.Input {
	return configbuilder.Input{
		PrimaryCandidate:      candidate,
		Settings:              d,
		LocalProxyUsername:    c.LocalProxyUsername,
		LocalProxyPassword:    c.LocalProxyPassword,
		UpstreamProxyType:     settings.UpstreamProxyType(c.UpstreamProxyType),
		UpstreamProxyHost:     c.UpstreamProxyHost,
		UpstreamProxyPort:     c.UpstreamProxyPort,
		UpstreamProxyUsername: c.UpstreamProxyUsername,
		UpstreamProxyPassword: c.UpstreamProxyPassword,
		BearerToken:           bearer,
		ControllerSecret:      s.controllerSecret,
		OwnProcessName:        ownProcessName(),
	}
}

func remoteconfigRefresh() {
	go func() {
		defer func() { _ = recover() }()
		controlplane.TriggerRemoteConfigRefresh()
	}()
}

// ---- credential renewal (port of startProxyPassRenewal + expiry watchdog) ----

func (s *Service) startCredentialRenewal(gen int, deadline time.Time) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.renewCancel = cancel
	s.mu.Unlock()

	s.goSafe("renewal", func() { renewalLoop(ctx, s, gen, &deadline) })

	// expiry watchdog
	s.goSafe("expiryWatchdog", func() {
		for {
			d := time.Until(deadline)
			if d <= 0 {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
			}
		}
		s.mu.Lock()
		if s.stopping || s.gen != gen || s.state != model.Connected {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		s.setLastError("Proxy credentials expired. Reconnect to retry.")
		s.requestDisconnect("installed credential deadline reached")
	})
}

func renewalLoop(ctx context.Context, s *Service, gen int, deadline *time.Time) {
	for {
		wait := time.Until(*deadline) - proxyPassFetchBudget
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		s.mu.Lock()
		if s.stopping || s.gen != gen || s.state != model.Connected {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		if !time.Now().Before(*deadline) {
			s.setLastError("Proxy credentials could not be renewed in time. Reconnect to retry.")
			s.requestDisconnect("proxy pass renewal deadline reached")
			return
		}
		pass, err := s.mintWithBudget(ctx, *deadline)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isFatal(err) {
				s.setLastError(s.friendlyError(err))
				s.requestDisconnect("credential renewal was rejected")
				return
			}
			logx.WarnErr(tag, fmt.Errorf("proxy pass renewal failed; retrying within its validity deadline: %w", err))
			retry := proxyPassRetry
			var he *guardian.HTTPError
			if errors.As(err, &he) && he.RetryAfterMs != nil {
				if d := time.Duration(*he.RetryAfterMs) * time.Millisecond; d > retry {
					retry = d
				}
			}
			if maxWait := time.Until(*deadline); retry > maxWait {
				retry = maxWait
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
				continue
			}
		}
		if err := validateProxyPass(pass); err != nil {
			s.setLastError(err.Error())
			s.requestDisconnect("renewed credential was invalid")
			return
		}
		s.mu.Lock()
		if s.gen != gen || s.stopping {
			s.mu.Unlock()
			return
		}
		s.bearerToken = pass.Token
		s.mu.Unlock()
		libbox.SetBearerToken(pass.Token)
		*deadline = credentialDeadline(pass.ExpiresAtEpochSeconds, time.Now())
		logx.Info(tag, "proxy pass replaced through the dynamic bearer token")
	}
}

func (s *Service) mintWithBudget(ctx context.Context, deadline time.Time) (guardian.ProxyPass, error) {
	budget := proxyPassFetchBudget
	if remaining := time.Until(deadline); remaining < budget {
		budget = remaining
	}
	type result struct {
		pass guardian.ProxyPass
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		pass, err := s.mintProxyPass()
		ch <- result{pass, err}
	}()
	select {
	case r := <-ch:
		return r.pass, r.err
	case <-ctx.Done():
		return guardian.ProxyPass{}, ctx.Err()
	case <-time.After(budget):
		return guardian.ProxyPass{}, errors.New("proxy pass renewal timed out")
	}
}

// ---- traffic (clash API /traffic stream) ----

func (s *Service) startTrafficReader(gen int) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.trafficCancel = cancel
	secret := s.controllerSecret
	s.mu.Unlock()

	s.goSafe("traffic", func() {
		defer cancel()
		client := &http.Client{Timeout: 0}
		lastNotify := time.Now()
		for ctx.Err() == nil {
			s.mu.Lock()
			if s.gen != gen || s.stopping || s.state != model.Connected {
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d/traffic", settings.ControllerPort), nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+secret)
			resp, err := client.Do(req)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
					continue
				}
			}
			dec := json.NewDecoder(resp.Body)
			for ctx.Err() == nil {
				var sample struct {
					Up   int64 `json:"up"`
					Down int64 `json:"down"`
				}
				if err := dec.Decode(&sample); err != nil {
					break
				}
				s.mu.Lock()
				changed := false
				if s.gen == gen && s.state == model.Connected {
					s.stats.TxRateBytesPerSec = sample.Up
					s.stats.RxRateBytesPerSec = sample.Down
					s.stats.SessionBytes += sample.Up + sample.Down
					changed = true
				}
				s.mu.Unlock()
				// Push live rates to the GUI about once a second — the
				// frontend only sees values through snapshot events.
				if changed && time.Since(lastNotify) >= 500*time.Millisecond {
					lastNotify = time.Now()
					s.notify()
				}
			}
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	})
}

// ---- health monitor + bounded recovery (port of startHealthMonitor) ----

var healthProbeURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://www.cloudflare.com/cdn-cgi/trace",
}

func (s *Service) startHealthMonitor(gen int) {
	s.goSafe("health", func() {
		healthLoop(s, gen)
	})
}

func healthLoop(s *Service, gen int) {
	failures := 0
	for {
		s.mu.Lock()
		if s.gen != gen || s.stopping || s.state != model.Connected {
			s.mu.Unlock()
			return
		}
		d := s.cfg.Get()
		creds := s.creds.Get()
		s.mu.Unlock()

		// The probe doubles as the latency measurement for the ping chip,
		// so it runs immediately after connect, then every 60s.
		healthy := false
		latency := 0
		latencyOk := false
		for _, url := range healthProbeURLs {
			if v, got := exitcheck.MeasureProxyLatencyMs(d.SocksPort, url, creds.LocalProxyUsername, creds.LocalProxyPassword); got {
				if !latencyOk {
					latency = v
					latencyOk = true
				}
				healthy = true
				break
			}
		}
		s.mu.Lock()
		if s.gen != gen || s.state != model.Connected {
			s.mu.Unlock()
			return
		}
		changed := false
		if healthy {
			if s.health != model.TunnelHealthy {
				s.health = model.TunnelHealthy
				changed = true
			}
			failures = 0
		} else {
			if s.health != model.TunnelUnreachable {
				s.health = model.TunnelUnreachable
				changed = true
			}
			failures++
		}
		if latencyOk {
			if s.pingMs == nil || *s.pingMs != latency {
				v := latency
				s.pingMs = &v
				changed = true
			}
		}
		candidate := s.activeCandidate
		s.mu.Unlock()
		if changed {
			s.notify()
		}

		if healthy || failures < 3 || !d.AutomaticRecovery || d.EffectiveCustomEdgeAddress() != "" {
			time.Sleep(60 * time.Second)
			continue
		}
		// confirm the direct path works before blaming the tunnel
		directWorks := true
		for _, url := range healthProbeURLs {
			req, _ := http.NewRequest("GET", url, nil)
			resp, err := controlplane.Client().Do(req)
			if err != nil {
				directWorks = false
				break
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				directWorks = false
				break
			}
		}
		if !directWorks {
			failures = 0
			time.Sleep(60 * time.Second)
			continue
		}
		s.mu.Lock()
		if s.gen != gen || s.state != model.Connected {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		if !s.recoveryBudget.tryAcquire(time.Now()) {
			logx.Warn(tag, "recovery budget exhausted; staying connected")
			time.Sleep(60 * time.Second)
			continue
		}
		alternate := s.pickAlternate(candidate)
		logx.Warn(tag, "confirmed proxy-path failure; bounded recovery within the selected country")
		s.recoverWith(gen, alternate)
		return
	}
}

func (s *Service) pickAlternate(current *model.ProxyCandidate) *model.ProxyCandidate {
	if current == nil {
		return nil
	}
	countries := s.servers.LoadCachedCountries()
	seen := map[string]bool{}
	var pool []model.ProxyCandidate
	for _, c := range countries {
		if !strings.EqualFold(c.Code, current.CountryCode) {
			continue
		}
		for _, cand := range serverlist.CandidatesForCountry(countries, c.Code) {
			if cand.Authority() == current.Authority() || seen[cand.Authority()] {
				continue
			}
			seen[cand.Authority()] = true
			pool = append(pool, cand)
		}
	}
	if len(pool) == 0 {
		return nil
	}
	alt := pool[rand.Intn(len(pool))]
	return &alt
}

// recoverWith swaps to an alternate candidate with a brief CONNECTING phase.
func (s *Service) recoverWith(gen int, alternate *model.ProxyCandidate) {
	s.mu.Lock()
	if s.stopping || s.gen != gen || s.state != model.Connected {
		s.mu.Unlock()
		return
	}
	gen++
	s.gen = gen
	inst := s.instance
	s.instance = nil
	if s.trafficCancel != nil {
		s.trafficCancel()
		s.trafficCancel = nil
	}
	if s.renewCancel != nil {
		s.renewCancel()
		s.renewCancel = nil
	}
	s.health = model.TunnelChecking
	s.pingMs = nil
	s.edgeIP = nil
	s.stats = VpnLiveStats{}
	s.connectedAt = nil
	s.state = model.Connecting
	s.statusLabel = "Reconnecting…"
	s.reconnecting = true
	s.activeCandidate = alternate
	s.mu.Unlock()
	s.notify()
	if inst != nil {
		_ = inst.Close()
	}
	s.goSafe("recovery", func() {
		if err := s.connectOnce(alternate); err != nil {
			s.failConnect(err, true)
		}
	})
}

// ---- exit IP check ----

func (s *Service) startExitCheck(gen int, d settings.Stored, creds storage.Credentials) {
	s.goSafe("exitCheck", func() {
		for attempt := 0; attempt < 3; attempt++ {
			s.mu.Lock()
			if s.gen != gen || s.state != model.Connected {
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
			info, err := exitcheck.FetchProxiedIPInfo(d.SocksPort, creds.LocalProxyUsername, creds.LocalProxyPassword, 15*time.Second)
			if err == nil {
				s.mu.Lock()
				if s.gen == gen && s.state == model.Connected {
					s.edgeIP = &info
					logx.Info(tag, "exit check: observed ip=%s, country=%s", info.IP, info.CountryCode)
				}
				s.mu.Unlock()
				s.notify()
				return
			}
			logx.WarnErr(tag, fmt.Errorf("exit check attempt %d failed (non-fatal): %w", attempt+1, err))
			time.Sleep(time.Duration(2*(attempt+1)) * time.Second)
		}
	})
}

// PingNow measures latency through the current local proxy (async).
func (s *Service) PingNow() {
	s.mu.Lock()
	if s.state != model.Connected {
		s.mu.Unlock()
		return
	}
	d := s.cfg.Get()
	creds := s.creds.Get()
	port := d.SocksPort
	probe := d.LatencyProbeURL
	s.mu.Unlock()
	go func() {
		ms, ok := exitcheck.MeasureProxyLatencyMs(port, probe, creds.LocalProxyUsername, creds.LocalProxyPassword)
		s.mu.Lock()
		if ok {
			v := ms
			s.pingMs = &v
		}
		s.mu.Unlock()
		s.notify()
	}()
}
