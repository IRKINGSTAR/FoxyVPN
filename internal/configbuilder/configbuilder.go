// Package configbuilder is a port of SingBoxConfigBuilder.kt: it builds the
// sing-box JSON configuration for the FoxyVPN MASQUE connection, using the
// fork's dynamic_bearer_token outbound. Split tunneling uses process_name
// route rules (Windows equivalent of Android package matching).
package configbuilder

import (
	"encoding/json"
	"fmt"
	"strings"

	"foxyvpn/internal/model"
	"foxyvpn/internal/settings"
)

const (
	defaultTunIPv4     = "172.19.0.1/30"
	defaultTunIPv6     = "fdfe:dcba:9876::1/126"
	defaultTunDNSIPv4  = "172.19.0.2"
	defaultTunDNSIPv6  = "fdfe:dcba:9876::2"
)

var localNetworkAddressesIPv4 = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
}

var localNetworkAddressesIPv6 = []string{
	"fc00::/7", "fe80::/10",
}

// Input carries everything the builder needs.
type Input struct {
	PrimaryCandidate model.ProxyCandidate
	Settings         settings.Stored
	LocalProxyUsername string
	LocalProxyPassword string
	UpstreamProxyType   settings.UpstreamProxyType
	UpstreamProxyHost   string
	UpstreamProxyPort   int
	UpstreamProxyUsername string
	UpstreamProxyPassword string
	BearerToken      string
	ControllerSecret string
	OwnProcessName   string
}

func port(v int) any { return v }

// Build returns the sing-box configuration JSON.
func Build(in Input) (string, error) {
	s := in.Settings
	if !(in.PrimaryCandidate.Port >= 1 && in.PrimaryCandidate.Port <= 65535 && settings.IsValidEdgeHost(in.PrimaryCandidate.Host)) {
		return "", fmt.Errorf("invalid MASQUE server address")
	}
	if !(s.SocksPort >= 1 && s.SocksPort <= 65535 && s.SocksPort != settings.ControllerPort) {
		return "", fmt.Errorf("local proxy port must be valid and must not use controller port %d", settings.ControllerPort)
	}
	if in.BearerToken == "" {
		return "", fmt.Errorf("a proxy pass is required")
	}
	if in.ControllerSecret == "" {
		return "", fmt.Errorf("controller authentication is required")
	}

	var localNetworkAddresses []string
	if s.IPMode.HasIpv4() {
		localNetworkAddresses = append(localNetworkAddresses, localNetworkAddressesIPv4...)
	}
	if s.IPMode.HasIpv6() {
		localNetworkAddresses = append(localNetworkAddresses, localNetworkAddressesIPv6...)
	}

	root := map[string]any{}
	root["log"] = map[string]any{"level": "info", "timestamp": true}
	root["certificate"] = map[string]any{"store": "mozilla"}

	// ---- DNS ----
	dnsServers := []any{map[string]any{"type": "local", "tag": "local-dns"}}
	hasBootstrapDns := s.BootstrapDNSProvider != settings.DnsDirectSystem && s.EffectiveBootstrapDohURL() != ""
	activeBootstrap := "local-dns"
	if hasBootstrapDns {
		srv, err := dohServerObject(s.EffectiveBootstrapDohURL(), "bootstrap-dns", "local-dns")
		if err != nil {
			return "", err
		}
		dnsServers = append(dnsServers, srv)
		activeBootstrap = "bootstrap-dns"
	}
	finalDns := "local-dns"
	if s.DNSProvider != settings.DnsDirectSystem {
		if s.EffectiveDohURL() == "" {
			return "", fmt.Errorf("DoH requires an HTTPS URL without credentials, query or fragment")
		}
		remote, err := dohServerObject(s.EffectiveDohURL(), "remote-dns", activeBootstrap)
		if err != nil {
			return "", err
		}
		remote["detour"] = "proxy-out"
		dnsServers = append(dnsServers, remote)
		finalDns = "remote-dns"
	}
	dns := map[string]any{
		"servers":       dnsServers,
		"final":         finalDns,
		"disable_cache": false,
	}
	if strat := s.IPMode.DnsStrategy(); strat != "" {
		dns["strategy"] = strat
	}
	root["dns"] = dns

	// ---- HTTP clients (uTLS engine) ----
	root["http_clients"] = []any{map[string]any{
		"tag":     "default-http-client",
		"engine":  "go",
		"version": 2,
		"tls": map[string]any{
			"utls": map[string]any{
				"enabled":     true,
				"fingerprint": s.UtlsFingerprint.Identifier(),
			},
		},
	}}

	// ---- Inbounds ----
	var inbounds []any
	if !s.ProxyOnlyMode {
		tun := map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"mtu":          s.MTU,
			"auto_route":   true,
			"strict_route": true,
			"platform":     map[string]any{"http_proxy": map[string]any{"enabled": false}},
		}
		var address, dnsAddress []string
		if s.IPMode.HasIpv4() {
			address = append(address, defaultTunIPv4)
			dnsAddress = append(dnsAddress, defaultTunDNSIPv4)
		}
		if s.IPMode.HasIpv6() {
			address = append(address, defaultTunIPv6)
			dnsAddress = append(dnsAddress, defaultTunDNSIPv6)
		}
		tun["address"] = address
		tun["dns_address"] = dnsAddress
		if s.BypassLocalNetwork && len(localNetworkAddresses) > 0 {
			tun["route_exclude_address"] = localNetworkAddresses
		}
		inbounds = append(inbounds, tun)
	}
	mixed := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      s.SocksBindAddress,
		"listen_port": port(s.SocksPort),
		"reuse_addr":  true,
	}
	if s.LocalProxyAuthEnabled {
		mixed["users"] = []any{map[string]any{
			"username": in.LocalProxyUsername,
			"password": in.LocalProxyPassword,
		}}
	}
	inbounds = append(inbounds, mixed)
	root["inbounds"] = inbounds

	// ---- Outbounds ----
	outbounds := []any{map[string]any{"type": "direct", "tag": "direct-out"}}

	candidate := in.PrimaryCandidate
	serverAddress := candidate.Host
	if edge := s.EffectiveCustomEdgeAddress(); edge != "" {
		serverAddress = edge
	}
	targetVersion := s.HTTPVersion.Number()

	nodeOutbound := map[string]any{
		"type":                     "http",
		"tag":                      "proxy-out",
		"server":                   serverAddress,
		"server_port":              port(candidate.Port),
		"domain_resolver":          activeBootstrap,
		"dynamic_bearer_token":     true,
		"version":                  targetVersion,
		"disable_version_fallback": true,
	}
	if targetVersion == 2 {
		nodeOutbound["max_concurrent_streams"] = s.MaxConcurrentStreams
		nodeOutbound["stream_receive_window"] = "16 MB"
		nodeOutbound["connection_receive_window"] = "32 MB"
		nodeOutbound["idle_timeout"] = "30s"
		nodeOutbound["keep_alive_period"] = "15s"
	}
	tls := map[string]any{
		"enabled":     true,
		"server_name": candidate.Host,
	}
	if targetVersion != 3 {
		tls["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": s.UtlsFingerprint.Identifier(),
		}
		switch s.TlsFragmentMode {
		case settings.FragmentOff:
		case settings.FragmentRecord:
			tls["record_fragment"] = true
		case settings.FragmentPacket:
			tls["fragment"] = true
			tls["fragment_fallback_delay"] = fmt.Sprintf("%dms", s.FragmentFallbackDelay)
		case settings.FragmentCombined:
			tls["fragment"] = true
			tls["record_fragment"] = true
			tls["fragment_fallback_delay"] = fmt.Sprintf("%dms", s.FragmentFallbackDelay)
		}
	}
	nodeOutbound["tls"] = tls
	hasUpstream := s.UpstreamProxyEnabled && in.UpstreamProxyHost != ""
	if hasUpstream {
		nodeOutbound["detour"] = "upstream-detour"
	}
	outbounds = append(outbounds, nodeOutbound)

	if hasUpstream {
		detour := map[string]any{
			"tag":             "upstream-detour",
			"server":          in.UpstreamProxyHost,
			"server_port":     port(in.UpstreamProxyPort),
			"domain_resolver": activeBootstrap,
		}
		if in.UpstreamProxyType == settings.UpstreamHTTP {
			detour["type"] = "http"
			detour["version"] = 1
			detour["dynamic_bearer_token"] = false
		} else {
			detour["type"] = "socks"
			detour["version"] = "5"
		}
		if in.UpstreamProxyUsername != "" {
			detour["username"] = in.UpstreamProxyUsername
			detour["password"] = in.UpstreamProxyPassword
		}
		outbounds = append(outbounds, detour)
	}
	root["outbounds"] = outbounds

	// ---- Route ----
	rules := []any{
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
		map[string]any{"port": 53, "action": "hijack-dns"},
		map[string]any{"port": 853, "action": "reject"},
	}
	if s.BypassLocalNetwork && len(localNetworkAddresses) > 0 {
		rules = append(rules, map[string]any{"ip_cidr": localNetworkAddresses, "outbound": "direct-out"})
	}
	if !s.IPMode.HasIpv6() {
		rules = append(rules, map[string]any{"ip_version": 6, "action": "reject"})
	}
	if !s.IPMode.HasIpv4() {
		rules = append(rules, map[string]any{"ip_version": 4, "action": "reject"})
	}

	ownProcess := in.OwnProcessName
	splitActive := len(s.ExcludedProcesses) > 0 || len(s.IncludedProcesses) > 0
	if s.SplitTunnelMode == settings.SplitInclude {
		var included []string
		for _, p := range s.IncludedProcesses {
			p = strings.TrimSpace(p)
			if p != "" && !strings.EqualFold(p, ownProcess) {
				included = append(included, p)
			}
		}
		if len(included) > 0 {
			rules = append(rules, map[string]any{"process_name": lowerAll(included), "outbound": "proxy-out"})
		}
	} else {
		excludedSet := map[string]bool{}
		for _, p := range s.ExcludedProcesses {
			p = strings.TrimSpace(p)
			if p != "" {
				excludedSet[strings.ToLower(p)] = true
			}
		}
		var excluded []string
		for p := range excludedSet {
			excluded = append(excluded, p)
		}
		if len(excluded) > 0 {
			rules = append(rules, map[string]any{"process_name": excluded, "outbound": "direct-out"})
		}
	}

	route := map[string]any{
		"rules":                   rules,
		"final":                   "proxy-out",
		"auto_detect_interface":   true,
		"find_process":            splitActive,
		"default_domain_resolver": activeBootstrap,
		"default_http_client":     "default-http-client",
	}
	if s.SplitTunnelMode == settings.SplitInclude && len(s.IncludedProcesses) > 0 {
		// include mode: everything not matched goes direct
		route["final"] = "direct-out"
	}
	root["route"] = route

	root["experimental"] = map[string]any{
		"cache_file": map[string]any{"enabled": false},
		"clash_api": map[string]any{
			"external_controller": fmt.Sprintf("%s:%d", settings.DefaultSocksBindAddress, settings.ControllerPort),
			"secret":              in.ControllerSecret,
			"default_mode":        "Rule",
		},
	}

	raw, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func dohServerObject(dohURL, tagValue, resolver string) (map[string]any, error) {
	u, err := parseURL(dohURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL %q: %w", dohURL, err)
	}
	server := strings.Trim(u.Host, "[]")
	obj := map[string]any{"type": "https", "tag": tagValue, "server": server}
	if u.Port != 443 {
		obj["server_port"] = u.Port
	}
	if u.Path != "" && u.Path != "/dns-query" {
		obj["path"] = u.Path
	}
	if hasLetter(server) {
		obj["domain_resolver"] = resolver
	}
	return obj, nil
}

type simpleURL struct {
	Host string
	Port int
	Path string
}

func parseURL(raw string) (simpleURL, error) {
	s := raw
	if !strings.HasPrefix(strings.ToLower(s), "https://") {
		return simpleURL{}, fmt.Errorf("not https")
	}
	s = s[len("https://"):]
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return simpleURL{}, fmt.Errorf("query or fragment not allowed")
	}
	hostPort := s
	path := ""
	if i := strings.Index(s, "/"); i >= 0 {
		hostPort = s[:i]
		path = s[i:]
	}
	port := 443
	host := hostPort
	if strings.HasPrefix(hostPort, "[") {
		if i := strings.Index(hostPort, "]"); i >= 0 {
			host = hostPort[1:i]
			rest := hostPort[i+1:]
			if strings.HasPrefix(rest, ":") {
				p := 0
				for _, c := range rest[1:] {
					if c < '0' || c > '9' {
						return simpleURL{}, fmt.Errorf("bad port")
					}
					p = p*10 + int(c-'0')
				}
				port = p
			}
		} else {
			return simpleURL{}, fmt.Errorf("bad host")
		}
	} else if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		host = hostPort[:i]
		p := 0
		for _, c := range hostPort[i+1:] {
			if c < '0' || c > '9' {
				return simpleURL{}, fmt.Errorf("bad port")
			}
			p = p*10 + int(c-'0')
		}
		port = p
	}
	if host == "" {
		return simpleURL{}, fmt.Errorf("no host")
	}
	return simpleURL{Host: host, Port: port, Path: path}, nil
}

func hasLetter(s string) bool {
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}
