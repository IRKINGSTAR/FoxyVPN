// User settings store: JSON on disk with Android-compatible defaults.
package settings

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	DefaultMTU                   = 1280
	MinMTU                       = 576
	MaxMTU                       = 9000
	ControllerPort               = 9090
	DefaultSocksBindAddress      = "127.0.0.1"
	AllInterfacesBindAddress     = "0.0.0.0"
	DefaultSocksPort             = 1080
	DefaultUpstreamProxyPort     = 1080
	DefaultFragmentFallbackDelay = 300
	DefaultMaxConcurrentStreams  = 32
	DefaultLatencyProbeURL       = "https://www.gstatic.com/generate_204"
)

type DnsProvider string

const (
	DnsDirectSystem DnsProvider = "DIRECT_SYSTEM"
	DnsGoogle       DnsProvider = "GOOGLE"
	DnsCloudflare   DnsProvider = "CLOUDFLARE"
	DnsQuad9        DnsProvider = "QUAD9"
	DnsCustom       DnsProvider = "CUSTOM"
)

func (d DnsProvider) DohURL() string {
	switch d {
	case DnsGoogle:
		return "https://8.8.8.8/dns-query"
	case DnsCloudflare:
		return "https://1.1.1.1/dns-query"
	case DnsQuad9:
		return "https://9.9.9.9/dns-query"
	}
	return ""
}

type HttpVersion string

const (
	HttpV1 HttpVersion = "HTTP_1"
	HttpV2 HttpVersion = "HTTP_2"
	HttpV3 HttpVersion = "HTTP_3"
)

func (h HttpVersion) Number() int {
	switch h {
	case HttpV1:
		return 1
	case HttpV3:
		return 3
	}
	return 2
}

type TlsFragmentMode string

const (
	FragmentOff      TlsFragmentMode = "OFF"
	FragmentRecord   TlsFragmentMode = "RECORD"
	FragmentPacket   TlsFragmentMode = "PACKET"
	FragmentCombined TlsFragmentMode = "COMBINED"
)

type UtlsFingerprint string

const (
	UtlsFirefox     UtlsFingerprint = "FIREFOX"
	UtlsChrome      UtlsFingerprint = "CHROME"
	UtlsSafari      UtlsFingerprint = "SAFARI"
	UtlsIos         UtlsFingerprint = "IOS"
	UtlsEdge        UtlsFingerprint = "EDGE"
	UtlsRandomized  UtlsFingerprint = "RANDOMIZED"
)

func (u UtlsFingerprint) Identifier() string {
	switch u {
	case UtlsChrome:
		return "chrome"
	case UtlsSafari:
		return "safari"
	case UtlsIos:
		return "ios"
	case UtlsEdge:
		return "edge"
	case UtlsRandomized:
		return "randomized"
	}
	return "firefox"
}

type IpMode string

const (
	IpDualStack  IpMode = "dual_stack"
	IpPreferV4   IpMode = "prefer_ipv4"
	IpPreferV6   IpMode = "prefer_ipv6"
	IpV4Only     IpMode = "ipv4_only"
	IpV6Only     IpMode = "ipv6_only"
)

func (m IpMode) HasIpv4() bool { return m != IpV6Only }
func (m IpMode) HasIpv6() bool { return m != IpV4Only }
func (m IpMode) DnsStrategy() string {
	switch m {
	case IpPreferV4:
		return "prefer_ipv4"
	case IpPreferV6:
		return "prefer_ipv6"
	case IpV4Only:
		return "ipv4_only"
	case IpV6Only:
		return "ipv6_only"
	}
	return ""
}

type UpstreamProxyType string

const (
	UpstreamSocks5 UpstreamProxyType = "SOCKS5"
	UpstreamHTTP   UpstreamProxyType = "HTTP"
)

type SplitTunnelMode string

const (
	SplitExclude SplitTunnelMode = "EXCLUDE"
	SplitInclude SplitTunnelMode = "INCLUDE"
)

// Stored holds only non-secret settings; secrets live in the DPAPI
// credential store (see internal/storage).
type Stored struct {
	BypassLocalNetwork      bool   `json:"bypassLocalNetwork"`
	AutomaticRecovery       bool   `json:"automaticRecovery"`
	ThemeMode               string `json:"themeMode"` // dark | light | system
	Language                string `json:"language"`  // fa | en
	LatencyProbeURL         string `json:"latencyProbeUrl,omitempty"`
	MTU                     int    `json:"mtu"`
	DNSProvider             DnsProvider `json:"dnsProvider"`
	CustomDohURL            string `json:"customDohUrl,omitempty"`
	BootstrapDNSProvider    DnsProvider `json:"bootstrapDnsProvider"`
	CustomBootstrapDohURL   string `json:"customBootstrapDohUrl,omitempty"`
	TlsFragmentMode         TlsFragmentMode `json:"tlsFragmentMode"`
	FragmentFallbackDelay   int    `json:"fragmentFallbackDelay"`
	UtlsFingerprint         UtlsFingerprint `json:"utlsFingerprint"`
	MaxConcurrentStreams    int    `json:"maxConcurrentStreams"`
	IPMode                  IpMode `json:"ipMode"`
	ProxyOnlyMode           bool   `json:"proxyOnlyMode"`
	// SystemProxy (nil = enabled) applies the local proxy to the Windows
	// system configuration while proxy-only mode is connected.
	SystemProxy             *bool  `json:"systemProxy,omitempty"`
	CustomEdgeAddress       string `json:"customEdgeAddress,omitempty"`
	HTTPVersion             HttpVersion `json:"httpVersion"`
	SocksPort               int    `json:"socksPort"`
	SocksBindAddress        string `json:"socksBindAddress"`
	LocalProxyAuthEnabled   bool   `json:"localProxyAuthEnabled"`
	UpstreamProxyEnabled    bool   `json:"upstreamProxyEnabled"`
	SplitTunnelMode         SplitTunnelMode `json:"splitTunnelMode"`
	ExcludedProcesses       []string `json:"excludedProcesses"`
	IncludedProcesses       []string `json:"includedProcesses"`
	// Cached account snapshot
	CachedRealIP      string `json:"cachedRealIp,omitempty"`
	CachedRealCountry string `json:"cachedRealCountry,omitempty"`
	CachedQuotaRemaining *int64 `json:"cachedQuotaRemaining,omitempty"`
	CachedQuotaMax       *int64 `json:"cachedQuotaMax,omitempty"`
	CachedIsUnlimited    bool   `json:"cachedIsUnlimited"`
	SelectedRegion       *Region `json:"selectedRegion,omitempty"`
}

type Region struct {
	CountryCode string `json:"countryCode"`
	CountryName string `json:"countryName"`
	CityCode    string `json:"cityCode"`
	CityName    string `json:"cityName"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
}

type Store struct {
	mu   sync.Mutex
	path string
	data Stored
}

// ProxyCredentials carries the secret settings needed for validation without
// importing the storage package (which depends on this one).
type ProxyCredentials struct {
	LocalProxyUsername    string
	LocalProxyPassword    string
	UpstreamProxyType     UpstreamProxyType
	UpstreamProxyHost     string
	UpstreamProxyPort     int
	UpstreamProxyUsername string
	UpstreamProxyPassword string
}

func Default() Stored {
	return Stored{
		BypassLocalNetwork:    true,
		AutomaticRecovery:     false,
		ThemeMode:             "system",
		Language:              "fa",
		LatencyProbeURL:       DefaultLatencyProbeURL,
		MTU:                   DefaultMTU,
		DNSProvider:           DnsGoogle,
		BootstrapDNSProvider:  DnsDirectSystem,
		TlsFragmentMode:       FragmentOff,
		FragmentFallbackDelay: DefaultFragmentFallbackDelay,
		UtlsFingerprint:       UtlsFirefox,
		MaxConcurrentStreams:  DefaultMaxConcurrentStreams,
		IPMode:                IpDualStack,
		HTTPVersion:           HttpV2,
		SocksPort:             DefaultSocksPort,
		SocksBindAddress:      DefaultSocksBindAddress,
		SplitTunnelMode:       SplitExclude,
	}
}

func AppDataDir() string {
	if dir := portableDir(); dir != "" {
		return dir
	}
	dir := os.Getenv("APPDATA")
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "FoxyVPN")
}

// portableDir returns "<exe dir>\data" when the exe sits next to a
// "portable.txt" marker (portable distribution), otherwise "".
func portableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exeDir := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(exeDir, "portable.txt")); err != nil {
		return ""
	}
	return filepath.Join(exeDir, "data")
}

// ExeDir returns the directory containing the running executable.
func ExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func Load() (*Store, error) {
	dir := AppDataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "settings.json")
	s := &Store{path: path, data: Default()}
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		merged := s.data
		if err := json.Unmarshal(raw, &merged); err == nil {
			s.data = merged
		}
	}
	s.sanitize()
	return s, nil
}

func (s *Store) sanitize() {
	d := &s.data
	if d.MTU == 0 {
		d.MTU = DefaultMTU
	}
	d.MTU = clamp(d.MTU, MinMTU, MaxMTU)
	if d.DNSProvider == "" {
		d.DNSProvider = DnsGoogle
	}
	if d.DNSProvider == "SYSTEM_DEFAULT" || d.DNSProvider == "ADGUARD" {
		d.DNSProvider = DnsGoogle
	}
	if d.BootstrapDNSProvider == "" {
		d.BootstrapDNSProvider = DnsDirectSystem
	}
	if d.TlsFragmentMode == "" {
		d.TlsFragmentMode = FragmentOff
	}
	if d.FragmentFallbackDelay == 0 {
		d.FragmentFallbackDelay = DefaultFragmentFallbackDelay
	}
	d.FragmentFallbackDelay = clamp(d.FragmentFallbackDelay, 50, 2000)
	if d.UtlsFingerprint == "" {
		d.UtlsFingerprint = UtlsFirefox
	}
	if d.MaxConcurrentStreams == 0 {
		d.MaxConcurrentStreams = DefaultMaxConcurrentStreams
	}
	d.MaxConcurrentStreams = clamp(d.MaxConcurrentStreams, 2, 128)
	if d.IPMode == "" {
		d.IPMode = IpDualStack
	}
	if d.HTTPVersion == "" {
		d.HTTPVersion = HttpV2
	}
	if d.SocksPort == 0 {
		d.SocksPort = DefaultSocksPort
	}
	if d.SocksBindAddress == "" {
		d.SocksBindAddress = DefaultSocksBindAddress
	}
	if d.SplitTunnelMode == "" {
		d.SplitTunnelMode = SplitExclude
	}
	if d.LatencyProbeURL == "" {
		d.LatencyProbeURL = DefaultLatencyProbeURL
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Get() Stored {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *Store) Update(mutate func(*Stored)) error {
	s.mu.Lock()
	mutate(&s.data)
	s.mu.Unlock()
	return s.Save()
}

// ---- effective values ----

func (d Stored) EffectiveDohURL() string {
	switch d.DNSProvider {
	case DnsCustom:
		return strings.TrimSpace(d.CustomDohURL)
	case DnsDirectSystem:
		return ""
	default:
		return d.DNSProvider.DohURL()
	}
}

func (d Stored) EffectiveBootstrapDohURL() string {
	switch d.BootstrapDNSProvider {
	case DnsCustom:
		return strings.TrimSpace(d.CustomBootstrapDohURL)
	case DnsDirectSystem:
		return ""
	default:
		return d.BootstrapDNSProvider.DohURL()
	}
}

func (d Stored) EffectiveCustomEdgeAddress() string {
	if IsValidEdgeHost(d.CustomEdgeAddress) {
		return d.CustomEdgeAddress
	}
	return ""
}

// EffectiveSystemProxy: the Windows system proxy follows the local proxy in
// proxy-only mode unless the user disabled it.
func (d Stored) EffectiveSystemProxy() bool {
	return d.SystemProxy == nil || *d.SystemProxy
}

// ---- validation ----

func IsValidIPv4(value string) bool {
	octets := strings.Split(value, ".")
	if len(octets) != 4 {
		return false
	}
	for _, o := range octets {
		if o == "" || len(o) > 3 {
			return false
		}
		for _, c := range o {
			if c < '0' || c > '9' {
				return false
			}
		}
		if len(o) > 1 && o[0] == '0' {
			return false
		}
		n := 0
		for _, c := range o {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func IsValidIpAddress(value string) bool {
	if value == "" {
		return false
	}
	if !strings.Contains(value, ":") {
		return IsValidIPv4(value)
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF:.", c) {
			return false
		}
	}
	ip := net.ParseIP(value)
	return ip != nil
}

func IsValidHostname(value string) bool {
	host := strings.TrimSuffix(strings.TrimSpace(value), ".")
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.Contains(host, ":") {
		return false
	}
	onlyDigitsDots := true
	for _, c := range host {
		if !(c >= '0' && c <= '9') && c != '.' {
			onlyDigitsDots = false
			break
		}
	}
	if onlyDigitsDots {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if c == '-' {
				continue
			}
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
				continue
			}
			return false
		}
	}
	return true
}

func IsValidProxyHost(value string) bool {
	host := strings.TrimSuffix(strings.Trim(strings.TrimSpace(value), "[]"), ".")
	if IsValidIpAddress(host) || IsValidHostname(host) {
		return true
	}
	if len(host) < 1 || len(host) > 63 {
		return false
	}
	hasLetter := false
	for _, c := range host {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		}
		if !(c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return hasLetter && !strings.HasPrefix(host, "-") && !strings.HasSuffix(host, "-")
}

func IsValidEdgeHost(value string) bool {
	host := strings.TrimSuffix(strings.TrimSpace(value), ".")
	return IsValidHostname(host) || IsValidIpAddress(host)
}

func IsValidDohURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		return false
	}
	rest := trimmed[len("https://"):]
	if rest == "" {
		return false
	}
	if strings.ContainsAny(rest, "@#?") {
		return false
	}
	host := rest
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") {
		hostNoPort, port, err := net.SplitHostPort(host)
		if err != nil {
			return false
		}
		if !IsValidIpAddress(strings.Trim(hostNoPort, "[]")) && !IsValidHostname(hostNoPort) {
			return false
		}
		p := 0
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
			p = p*10 + int(c-'0')
		}
		return p >= 1 && p <= 65535
	}
	return IsValidIpAddress(strings.Trim(host, "[]")) || IsValidHostname(host)
}

func IsValidProbeURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		return false
	}
	rest := trimmed[len("https://"):]
	if rest == "" || strings.ContainsAny(rest, "@#") {
		return false
	}
	host := rest
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") {
		_, port, err := net.SplitHostPort(host)
		if err != nil {
			return false
		}
		p := 0
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
			p = p*10 + int(c-'0')
		}
		if p < 1 || p > 65535 {
			return false
		}
	}
	return true
}

func IsValidLocalPort(port int) bool {
	return port >= 1 && port <= 65535 && port != ControllerPort
}

func IsValidLocalProxyCredentials(username, password string) bool {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return false
	}
	if strings.Contains(username, ":") {
		return false
	}
	if hasISOControl(username) || hasISOControl(password) {
		return false
	}
	return len(username) >= 1 && len(username) <= 255 && len(password) >= 1 && len(password) <= 255
}

func IsValidUpstreamProxyCredentials(t UpstreamProxyType, username, password string) bool {
	if username == "" && password == "" {
		return true
	}
	if strings.TrimSpace(username) == "" || hasISOControl(username) || hasISOControl(password) {
		return false
	}
	switch t {
	case UpstreamSocks5:
		return len(username) >= 1 && len(username) <= 255 && len(password) >= 1 && len(password) <= 255
	case UpstreamHTTP:
		return !strings.Contains(username, ":") && len(username) <= 255 && len(password) <= 255
	}
	return false
}

func hasISOControl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func IsLocalProxyLoop(host string, port, mixedPort int) bool {
	normalized := strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	loopback := normalized == "localhost" || normalized == "::1" || normalized == "::ffff:127.0.0.1"
	if !loopback && IsValidIpAddress(normalized) {
		if ip := net.ParseIP(normalized); ip != nil && ip.IsLoopback() {
			loopback = true
		}
	}
	isLocal := loopback || normalized == "0.0.0.0" || normalized == "::"
	return isLocal && (port == mixedPort || port == ControllerPort)
}

func (s *Store) ValidateForConnect(d Stored, c ProxyCredentials) error {
	if !IsValidLocalPort(d.SocksPort) {
		return fmt.Errorf("local proxy port %d is invalid or reserved (%d is the controller port)", d.SocksPort, ControllerPort)
	}
	if d.SocksBindAddress != DefaultSocksBindAddress && d.SocksBindAddress != AllInterfacesBindAddress {
		return fmt.Errorf("local proxy listen address must be %s or %s", DefaultSocksBindAddress, AllInterfacesBindAddress)
	}
	if d.LocalProxyAuthEnabled {
		if !IsValidLocalProxyCredentials(c.LocalProxyUsername, c.LocalProxyPassword) {
			return fmt.Errorf("local proxy credentials are invalid")
		}
	}
	if d.ProxyOnlyMode {
		// no tun-specific requirements
	} else {
		if d.IPMode.HasIpv6() && d.MTU < 1280 {
			return fmt.Errorf("IPv6 requires a tunnel MTU of at least 1280")
		}
		if d.SplitTunnelMode == SplitInclude && len(d.IncludedProcesses) == 0 {
			return fmt.Errorf("select at least one program to include in the VPN")
		}
	}
	if d.DNSProvider != DnsDirectSystem && !IsValidDohURL(d.EffectiveDohURL()) {
		return fmt.Errorf("DoH requires a valid HTTPS URL without credentials, query or fragment")
	}
	if d.BootstrapDNSProvider != DnsDirectSystem && !IsValidDohURL(d.EffectiveBootstrapDohURL()) {
		return fmt.Errorf("bootstrap DoH requires a valid HTTPS URL")
	}
	if d.UpstreamProxyEnabled {
		if !IsValidProxyHost(c.UpstreamProxyHost) || c.UpstreamProxyPort < 1 || c.UpstreamProxyPort > 65535 {
			return fmt.Errorf("set a valid upstream proxy address before connecting")
		}
		if !IsValidUpstreamProxyCredentials(c.UpstreamProxyType, c.UpstreamProxyUsername, c.UpstreamProxyPassword) {
			return fmt.Errorf("upstream proxy credentials are invalid")
		}
		if IsLocalProxyLoop(c.UpstreamProxyHost, c.UpstreamProxyPort, d.SocksPort) {
			return fmt.Errorf("upstream proxy must not point to a FoxyVPN listener")
		}
		if c.UpstreamProxyType == UpstreamHTTP && d.HTTPVersion == HttpV3 {
			return fmt.Errorf("HTTP/3 (QUIC) is not supported over an upstream HTTP proxy")
		}
	}
	return nil
}
