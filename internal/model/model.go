// Package model is a port of com.vauth.foxyvpn.data.model.Models.kt.
package model

import "fmt"

type ConnectionState int

const (
	Disconnected ConnectionState = iota
	Connecting
	Connected
)

func (s ConnectionState) String() string {
	switch s {
	case Disconnected:
		return "DISCONNECTED"
	case Connecting:
		return "CONNECTING"
	case Connected:
		return "CONNECTED"
	}
	return "?"
}

type Protocol struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type ServerNode struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Protocols   []Protocol `json:"protocols"`
}

type City struct {
	Name    string       `json:"name"`
	Code    string       `json:"code"`
	Servers []ServerNode `json:"servers"`
}

type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

type ProxyCandidate struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	CountryCode string `json:"countryCode"`
	CountryName string `json:"countryName"`
	CityCode    string `json:"cityCode"`
}

func (c ProxyCandidate) Authority() string {
	host := c.Host
	if containsColon(host) {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, c.Port)
}

func containsColon(s string) bool {
	for _, r := range s {
		if r == ':' {
			return true
		}
	}
	return false
}

type Entitlement struct {
	MaxBytes         *int64 `json:"maxBytes"`
	LimitedBandwidth bool   `json:"limitedBandwidth"`
	QuotaRemaining   *int64 `json:"quotaRemaining"`
}

type RuntimeAuth struct {
	AccessToken         string `json:"accessToken"`
	RefreshToken        string `json:"refreshToken,omitempty"`
	ExpiresAtEpochSeconds int64 `json:"expiresAtEpochSeconds"`
}

func (a RuntimeAuth) String() string {
	return fmt.Sprintf("RuntimeAuth(expiresAtEpochSeconds=%d)", a.ExpiresAtEpochSeconds)
}

const (
	RecommendedCountryCode = "REC"
	RecommendedCountryName = "Recommended"
)

func NormalizeCountryName(code, rawName string) string {
	if equalFold(code, RecommendedCountryCode) ||
		equalFold(rawName, "Recomended") ||
		equalFold(rawName, RecommendedCountryName) {
		return RecommendedCountryName
	}
	return rawName
}

func (c Country) DisplayName() string { return NormalizeCountryName(c.Code, c.Name) }
func (c ProxyCandidate) DisplayName() string {
	return NormalizeCountryName(c.CountryCode, c.CountryName)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// TunnelHealth mirrors the Android enum.
type TunnelHealth int

const (
	TunnelUnknown TunnelHealth = iota
	TunnelChecking
	TunnelHealthy
	TunnelNoNetwork
	TunnelUnreachable
)

func (h TunnelHealth) String() string {
	switch h {
	case TunnelChecking:
		return "CHECKING"
	case TunnelHealthy:
		return "HEALTHY"
	case TunnelNoNetwork:
		return "NO_NETWORK"
	case TunnelUnreachable:
		return "UNREACHABLE"
	}
	return "UNKNOWN"
}
