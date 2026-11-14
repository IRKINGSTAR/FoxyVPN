// Mozilla VPN server directory from Remote Settings, with local cache.
package serverlist

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"foxyvpn/internal/controlplane"
	"foxyvpn/internal/logx"
	"foxyvpn/internal/model"
	"foxyvpn/internal/remoteconfig"
	"foxyvpn/internal/settings"
)

const tag = "ServerList"

const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

var excludedCountryNames = map[string]bool{"catchall anycast": true}

type Client struct {
	cachePath string
	client    *http.Client
}

func New() *Client {
	return &Client{
		cachePath: filepath.Join(settings.AppDataDir(), "vpn_serverlist_cache.json"),
		client:    controlplane.Client(),
	}
}

func (c *Client) HasFreshCache() bool {
	st, err := os.Stat(c.cachePath)
	if err != nil {
		return false
	}
	age := time.Since(st.ModTime())
	return age >= 0 && age < 6*time.Hour
}

func (c *Client) FetchCountries() ([]model.Country, error) {
	req, err := http.NewRequest("GET", remoteSettingsURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range remoteconfig.ControlPlaneHeaders() {
		if !strings.EqualFold(k, "Accept-Encoding") {
			req.Header.Set(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", remoteconfig.ControlPlaneUserAgent())
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Remote Settings fetch failed: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	countries := parseRecords(string(raw))
	if len(countries) == 0 {
		return nil, fmt.Errorf("server directory contains no locations")
	}
	c.saveCache(string(raw))
	logx.Info(tag, "fetched %d countries from Remote Settings", len(countries))
	return countries, nil
}

func (c *Client) LoadCachedCountries() []model.Country {
	raw, err := os.ReadFile(c.cachePath)
	if err != nil {
		return nil
	}
	parsed := parseRecords(string(raw))
	if len(parsed) > 0 {
		logx.Debug(tag, "loaded %d countries from local cache", len(parsed))
	}
	return parsed
}

func (c *Client) saveCache(raw string) {
	tmp := c.cachePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(raw), 0o600); err != nil {
		logx.Warn(tag, "failed to save server list cache: %v", err)
		return
	}
	if err := os.Rename(tmp, c.cachePath); err != nil {
		logx.Warn(tag, "failed to save server list cache: %v", err)
	}
}

type rawRecord struct {
	Country json.RawMessage `json:"country"`
}

func parseRecords(raw string) []model.Country {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var body struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return nil
	}
	var countries []model.Country
	for _, rec := range body.Data {
		var record struct {
			Country json.RawMessage `json:"country"`
		}
		if err := json.Unmarshal(rec, &record); err != nil {
			continue
		}
		countryJSON := rec
		if len(record.Country) > 0 {
			countryJSON = record.Country
		}
		country := parseCountry(countryJSON)
		if country.Code == "" || len(country.Cities) == 0 {
			continue
		}
		if excludedCountryNames[strings.ToLower(strings.TrimSpace(country.Name))] {
			continue
		}
		countries = append(countries, country)
	}
	// group by code, merge cities, dedupe servers
	byCode := map[string][]model.Country{}
	var order []string
	for _, c := range countries {
		if _, ok := byCode[c.Code]; !ok {
			order = append(order, c.Code)
		}
		byCode[c.Code] = append(byCode[c.Code], c)
	}
	var out []model.Country
	for _, code := range order {
		locs := byCode[code]
		first := locs[0]
		cityMap := map[string][]model.City{}
		var cityOrder []string
		for _, loc := range locs {
			for _, city := range loc.Cities {
				if _, ok := cityMap[city.Code]; !ok {
					cityOrder = append(cityOrder, city.Code)
				}
				cityMap[city.Code] = append(cityMap[city.Code], city)
			}
		}
		var cities []model.City
		for _, cityCode := range cityOrder {
			instances := cityMap[cityCode]
			city := instances[0]
			serverMap := map[string]model.ServerNode{}
			var serverOrder []string
			for _, inst := range instances {
				for _, srv := range inst.Servers {
					key := strings.ToLower(srv.Hostname) + ":" + fmt.Sprint(srv.Port)
					if _, ok := serverMap[key]; !ok {
						serverOrder = append(serverOrder, key)
					}
					existing, ok := serverMap[key]
					if ok {
						existing.Quarantined = existing.Quarantined || srv.Quarantined
						serverMap[key] = existing
						continue
					}
					serverMap[key] = srv
				}
			}
			var servers []model.ServerNode
			for _, key := range serverOrder {
				servers = append(servers, serverMap[key])
			}
			city.Servers = servers
			cities = append(cities, city)
		}
		first.Cities = cities
		out = append(out, first)
	}
	return out
}

func parseCountry(raw json.RawMessage) model.Country {
	var obj struct {
		Code   string          `json:"code"`
		Name   string          `json:"name"`
		Cities []json.RawMessage `json:"cities"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return model.Country{}
	}
	country := model.Country{
		Code: strings.ToUpper(strings.TrimSpace(obj.Code)),
		Name: model.NormalizeCountryName(strings.ToUpper(strings.TrimSpace(obj.Code)), obj.Name),
	}
	for _, cityRaw := range obj.Cities {
		if city := parseCity(cityRaw); city.Code != "" {
			country.Cities = append(country.Cities, city)
		}
	}
	return country
}

func parseCity(raw json.RawMessage) model.City {
	var obj struct {
		Name    string            `json:"name"`
		Code    string            `json:"code"`
		Servers []json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return model.City{}
	}
	city := model.City{
		Name: obj.Name,
		Code: strings.ToUpper(strings.TrimSpace(obj.Code)),
	}
	for _, srvRaw := range obj.Servers {
		var srv struct {
			Hostname    string          `json:"hostname"`
			Port        int             `json:"port"`
			Quarantined bool            `json:"quarantined"`
			Protocols   []json.RawMessage `json:"protocols"`
		}
		if err := json.Unmarshal(srvRaw, &srv); err != nil {
			continue
		}
		node := model.ServerNode{
			Hostname:    srv.Hostname,
			Port:        srv.Port,
			Quarantined: srv.Quarantined,
		}
		for _, protoRaw := range srv.Protocols {
			var p struct {
				Name string `json:"name"`
				Host string `json:"host"`
				Port int    `json:"port"`
			}
			if err := json.Unmarshal(protoRaw, &p); err != nil {
				continue
			}
			node.Protocols = append(node.Protocols, model.Protocol{Name: p.Name, Host: p.Host, Port: p.Port})
		}
		city.Servers = append(city.Servers, node)
	}
	return city
}

// DefaultConnectTarget picks the connect host/port for a server node.
func DefaultConnectTarget(server model.ServerNode) (string, int, bool) {
	for _, proto := range server.Protocols {
		if proto.Name == "connect" {
			host := proto.Host
			if host == "" {
				host = server.Hostname
			}
			port := proto.Port
			if port == 0 {
				port = server.Port
			}
			if settings.IsValidEdgeHost(host) && port >= 1 && port <= 65535 {
				return host, port, true
			}
		}
	}
	if len(server.Protocols) == 0 {
		if settings.IsValidEdgeHost(server.Hostname) && server.Port >= 1 && server.Port <= 65535 {
			return server.Hostname, server.Port, true
		}
	}
	return "", 0, false
}

// CandidatesForCountry lists connect candidates for a country.
func CandidatesForCountry(countries []model.Country, countryCode string) []model.ProxyCandidate {
	var out []model.ProxyCandidate
	for _, country := range countries {
		if !strings.EqualFold(country.Code, countryCode) {
			continue
		}
		for _, city := range country.Cities {
			for _, server := range city.Servers {
				if server.Quarantined {
					continue
				}
				host, port, ok := DefaultConnectTarget(server)
				if !ok {
					continue
				}
				out = append(out, model.ProxyCandidate{
					Host:        host,
					Port:        port,
					CountryCode: country.Code,
					CountryName: country.DisplayName(),
					CityCode:    city.Code,
				})
			}
		}
	}
	return out
}

// CandidatesForCity filters candidates by city.
func CandidatesForCity(countries []model.Country, countryCode, cityCode string) []model.ProxyCandidate {
	var out []model.ProxyCandidate
	for _, c := range CandidatesForCountry(countries, countryCode) {
		if strings.EqualFold(c.CityCode, cityCode) {
			out = append(out, c)
		}
	}
	return out
}

// PreferredConnectionCandidates filters candidates for the saved region.
func PreferredConnectionCandidates(candidates []model.ProxyCandidate, saved *model.ProxyCandidate) []model.ProxyCandidate {
	if saved == nil {
		var recommended []model.ProxyCandidate
		for _, c := range candidates {
			if strings.EqualFold(c.CountryCode, model.RecommendedCountryCode) {
				recommended = append(recommended, c)
			}
		}
		if len(recommended) > 0 {
			return recommended
		}
		if len(candidates) == 0 {
			return nil
		}
		first := candidates[0].CountryCode
		for _, c := range candidates {
			if strings.EqualFold(c.CountryCode, first) {
				return []model.ProxyCandidate{c}
			}
		}
		return nil
	}
	var country []model.ProxyCandidate
	for _, c := range candidates {
		if strings.EqualFold(c.CountryCode, saved.CountryCode) {
			country = append(country, c)
		}
	}
	for _, c := range country {
		if strings.EqualFold(c.Host, saved.Host) && c.Port == saved.Port {
			return []model.ProxyCandidate{c}
		}
	}
	var city []model.ProxyCandidate
	for _, c := range country {
		if strings.EqualFold(c.CityCode, saved.CityCode) {
			city = append(city, c)
		}
	}
	if len(city) > 0 {
		return city
	}
	return country
}
