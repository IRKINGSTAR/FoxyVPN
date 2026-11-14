// Package controlplane is the Windows port of ControlPlaneHttp.kt: the shared
// HTTPS client used for all Mozilla endpoints, with a uTLS Firefox fingerprint
// (Fastly rejects stock Go TLS), a shared cookie jar, pre-seeded DoH
// bootstrap resolution, and optional binding of sockets to the physical
// interface so control traffic never loops through our own TUN.
package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/sys/windows"

	"foxyvpn/internal/remoteconfig"
	"foxyvpn/internal/settings"
)

// ---- Cookie jar (port of SimpleCookieJar) ----

type CookieJar struct {
	mu      sync.Mutex
	cookies map[string]map[string]http.Cookie // host -> name -> cookie
}

func NewCookieJar() *CookieJar {
	return &CookieJar{cookies: map[string]map[string]http.Cookie{}}
}

func jarKey(u *url.URL) string {
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), ".")
}

func (j *CookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), ".")
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		if !c.Expires.IsZero() && time.Now().After(c.Expires) {
			delete(j.cookies[host], c.Name)
			continue
		}
		if j.cookies[host] == nil {
			j.cookies[host] = map[string]http.Cookie{}
		}
		j.cookies[host][c.Name] = *c
	}
}

func (j *CookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	host := jarKey(u)
	now := time.Now()
	var out []*http.Cookie
	for name, c := range j.cookies[host] {
		if !c.Expires.IsZero() && now.After(c.Expires) {
			delete(j.cookies[host], name)
			continue
		}
		cc := c
		out = append(out, &cc)
	}
	return out
}

// SnapshotAll returns every stored cookie (port of snapshotAll).
func (j *CookieJar) SnapshotAll() []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []*http.Cookie
	for _, perHost := range j.cookies {
		for _, c := range perHost {
			cc := c
			out = append(out, &cc)
		}
	}
	return out
}

// InstallForced installs a cookie for a specific host and also mirrors it to
// the other Mozilla control-plane hosts (port of installChallengeCookies).
func (j *CookieJar) InstallForced(cookie http.Cookie, hosts []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, h := range hosts {
		host := strings.TrimPrefix(strings.ToLower(h), ".")
		if j.cookies[host] == nil {
			j.cookies[host] = map[string]http.Cookie{}
		}
		c := cookie
		c.Domain = host
		j.cookies[host][c.Name] = c
	}
}

// Clear removes all cookies.
func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = map[string]map[string]http.Cookie{}
}

// ---- Physical-interface binding (Windows VpnService.protect equivalent) ----

var (
	bindMu        sync.Mutex
	bindEnabled   bool
	bindV4IfIndex uint32
	bindV6IfIndex uint32
)

// EnableInterfaceBinding activates binding of new control-plane sockets to
// the given interface index (the default physical interface). It prevents
// the TUN from capturing our own requests. Pass 0 to disable.
func EnableInterfaceBinding(v4Index, v6Index uint32) {
	bindMu.Lock()
	defer bindMu.Unlock()
	bindEnabled = v4Index != 0 || v6Index != 0
	bindV4IfIndex = v4Index
	bindV6IfIndex = v6Index
}

func bindControl(_, _ string, _ syscall.RawConn) error { return nil }

func getBestInterface(sock windows.Sockaddr) (uint32, error) {
	var idx uint32
	if err := windows.GetBestInterfaceEx(sock, &idx); err != nil {
		return 0, err
	}
	return idx, nil
}

func applyBindControl(network, _ string, rc syscall.RawConn) error {
	bindMu.Lock()
	enabled := bindEnabled
	v4, v6 := bindV4IfIndex, bindV6IfIndex
	bindMu.Unlock()
	if !enabled {
		return nil
	}
	var sockErr error
	rc.Control(func(fd uintptr) {
		if network == "tcp4" || network == "udp4" {
			if v4 == 0 {
				return
			}
			// IP_UNICAST_IF = 31, interface index in network byte order
			sockErr = setSockOptInt(fd, syscall.IPPROTO_IP, 31, int(networkOrder(v4)))
		} else if network == "tcp6" || network == "udp6" {
			if v6 == 0 {
				return
			}
			// IPV6_UNICAST_IF = 31
			sockErr = setSockOptInt(fd, syscall.IPPROTO_IPV6, 31, int(v6))
		}
	})
	return sockErr
}

func networkOrder(v uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return binary.BigEndian.Uint32(b)
}

func setSockOptInt(fd uintptr, level, opt, value int) error {
	return windows.SetsockoptInt(windows.Handle(fd), level, opt, value)
}

// DefaultInterfaceIndices finds the best physical interface for reaching the
// internet, avoiding our own TUN when possible.
func DefaultInterfaceIndices() (v4, v6 uint32) {
	v4, v6 = bestInterface("8.8.8.8"), bestInterface6("2001:4860:4860::8888")
	return
}

func bestInterface(target string) uint32 {
	ra, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return 0
	}
	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], ra.IP.To4())
	idx, err := getBestInterface(sa)
	if err != nil {
		return 0
	}
	return idx
}

func bestInterface6(target string) uint32 {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip := ipnet.IP.To16(); ip != nil && ipnet.IP.To4() == nil && !ipnet.IP.IsLoopback() {
					return uint32(ifc.Index)
				}
			}
		}
	}
	return 0
}

// ---- DoH bootstrap resolver (port of getOrCreateDoh pre-seeded hosts) ----

var preSeeded = map[string][]string{
	"dns.google":          {"8.8.8.8", "8.8.4.4"},
	"cloudflare-dns.com":  {"1.1.1.1", "1.0.0.1"},
	"one.one.one.one":     {"1.1.1.1", "1.0.0.1"},
	"dns.quad9.net":       {"9.9.9.9", "149.112.112.112"},
}

func bootstrapResolver(dohURL string) func(ctx context.Context, network, address string) (net.Conn, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return nil
	}
	host := strings.Trim(u.Hostname(), "[]")
	var seeds []string
	if settings.IsValidIpAddress(host) {
		seeds = []string{host}
	} else {
		seeds = preSeeded[host]
	}
	if len(seeds) == 0 {
		return nil
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// If the target is the DoH host itself, use pre-seeded IPs directly.
		hostname := address
		if h, _, err := net.SplitHostPort(address); err == nil {
			hostname = h
		}
		if strings.EqualFold(hostname, host) {
			for _, s := range seeds {
				if strings.Contains(network, "4") && !strings.Contains(s, ":") ||
					strings.Contains(network, "6") && strings.Contains(s, ":") {
					d := &net.Dialer{Timeout: 10 * time.Second, Control: applyBindControl}
					return d.DialContext(ctx, network, net.JoinHostPort(s, portOf(address)))
				}
			}
		}
		d := &net.Dialer{Timeout: 10 * time.Second, Control: applyBindControl}
		return d.DialContext(ctx, network, address)
	}
}

func portOf(address string) string {
	if _, p, err := net.SplitHostPort(address); err == nil {
		return p
	}
	if strings.HasSuffix(address, ":443") {
		return "443"
	}
	return "443"
}

// resolveWithBootstrap resolves hostname for DoH-provided URLs.
func resolveWithBootstrap(ctx context.Context, dohURL, hostname string) ([]net.IP, error) {
	// For the pre-seeded providers we hardcode resolution of the DoH server
	// itself; other names go through the system resolver.
	if seeds, ok := preSeeded[hostname]; ok {
		var ips []net.IP
		for _, s := range seeds {
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
			}
		}
		return ips, nil
	}
	var r net.Resolver
	return r.LookupIP(ctx, "ip", hostname)
}

// ---- Client construction ----

var (
	clientOnce sync.Once
	shared     *http.Client
	noRedirect *http.Client
	Jar        = NewCookieJar()
)

// dialFirefoxTLS presents a Firefox ClientHello (uTLS HelloFirefox_Auto) with
// the fingerprint's native ALPN (h2 + http/1.1). Since November 2026 the
// Fastly edge in front of Mozilla endpoints rejects stock Go TLS ClientHellos
// with HTTP 406 / EOF, and rejects Firefox-looking hellos that offer only
// http/1.1 — exactly as documented by the reference Go client.
func dialFirefoxTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rawDial := &net.Dialer{Timeout: 15 * time.Second, Control: applyBindControl}
	conn, err := rawDial.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	cfg := &utls.Config{ServerName: host, MinVersion: utls.VersionTLS12}
	uconn := utls.UClient(conn, cfg, utls.HelloFirefox_Auto)
	hsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := uconn.HandshakeContext(hsCtx); err != nil {
		conn.Close()
		return nil, err
	}
	return uconn, nil
}

// DialTLSContext is exported for satellite clients (challenge solver).
func DialTLSContext(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return dialFirefoxTLS(ctx, network, addr)
}

// NewFirefoxTLSTransport builds an HTTP/2-capable transport over the Firefox
// uTLS dialer (the edge negotiates h2).
func NewFirefoxTLSTransport() http.RoundTripper {
	return &http2.Transport{
		DialTLSContext: DialTLSContext,
	}
}

// Client returns the shared control-plane HTTP client (redirects allowed,
// used for Guardian / Remote Settings / misc GETs).
func Client() *http.Client {
	clientOnce.Do(func() {
		shared = &http.Client{
			Transport: NewFirefoxTLSTransport(),
			Jar:       Jar,
			Timeout:   120 * time.Second,
		}
		noRedirect = &http.Client{
			Transport: NewFirefoxTLSTransport(),
			Jar:       Jar,
			Timeout:   120 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	})
	return shared
}

// NoRedirectClient is the FxA-style client that never follows redirects
// (port of FxaAuthRepository's client).
func NoRedirectClient() *http.Client {
	Client()
	return noRedirect
}

// SimpleGet performs a GET with the component headers applied.
func SimpleGet(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(req, headers)
	return Client().Do(req)
}

func applyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		// Go rejects setting these manually; skip gracefully.
		switch strings.ToLower(k) {
		case "host", "content-length", "accept-encoding", "user-agent":
			if strings.EqualFold(k, "user-agent") {
				req.Header.Set(k, v)
			}
			continue
		}
		req.Header.Set(k, v)
	}
}

// ApplyComponentHeaders applies the given remote-config headers.
func ApplyComponentHeaders(req *http.Request, headers map[string]string) {
	applyHeaders(req, headers)
}

// DNSLookupFor resolves a hostname honoring the bootstrap DoH pre-seed map.
func DNSLookupFor(ctx context.Context, dohURL, hostname string) ([]net.IP, error) {
	return resolveWithBootstrap(ctx, dohURL, hostname)
}

// Sha256Hex is a small helper used by the challenge solver.
func Sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

// TriggerRemoteConfigRefresh pulls the remote header config once.
func TriggerRemoteConfigRefresh() {
	remoteconfig.Refresh(Client())
}
