// verify exercises the control plane end-to-end without login:
// remote config fetch -> server list fetch -> config build -> libbox.CheckConfig.
package main

import (
	"fmt"
	"os"

	"github.com/sagernet/sing-box/experimental/libbox"

	"foxyvpn/internal/configbuilder"
	"foxyvpn/internal/controlplane"
	"foxyvpn/internal/logx"
	"foxyvpn/internal/model"
	"foxyvpn/internal/remoteconfig"
	"foxyvpn/internal/serverlist"
	"foxyvpn/internal/settings"
	"foxyvpn/internal/storage"
)

func main() {
	logx.Info("verify", "starting control-plane verification")

	// 1. remote config
	remoteconfig.Init()
	controlplane.TriggerRemoteConfigRefresh()
	fmt.Printf("remote config: v%d, UA=%s\n", remoteconfig.Current().Version, remoteconfig.ControlPlaneUserAgent())

	// 2. server list
	client := serverlist.New()
	countries, err := client.FetchCountries()
	if err != nil {
		fmt.Println("server list fetch FAILED:", err)
		os.Exit(1)
	}
	totalServers := 0
	for _, c := range countries {
		for _, city := range c.Cities {
			totalServers += len(city.Servers)
		}
	}
	fmt.Printf("server list OK: %d countries, %d servers\n", len(countries), totalServers)
	if len(countries) > 0 {
		fmt.Printf("first country: %s (%s) cities=%d\n", countries[0].DisplayName(), countries[0].Code, len(countries[0].Cities))
	}

	// 3. config build + check
	var candidates []model.ProxyCandidate
	for _, c := range countries {
		candidates = append(candidates, serverlist.CandidatesForCountry(countries, c.Code)...)
		if len(candidates) > 0 {
			break
		}
	}
	if len(candidates) == 0 {
		fmt.Println("no connect candidates found")
		os.Exit(1)
	}
	cand := candidates[0]
	cfgStore, err := settings.Load()
	if err != nil {
		fmt.Println("settings load failed:", err)
		os.Exit(1)
	}
	d := cfgStore.Get()
	// TUNNEL=1 validates the tun-inbound configuration instead of proxy-only.
	if os.Getenv("TUNNEL") == "1" {
		d.ProxyOnlyMode = false
		d.SplitTunnelMode = settings.SplitExclude
		d.ExcludedProcesses = nil
		d.IncludedProcesses = nil
	} else {
		d.ProxyOnlyMode = true // tunnel mode would need wintun/admin
	}
	content, err := configbuilder.Build(configbuilder.Input{
		PrimaryCandidate: cand,
		Settings:         d,
		BearerToken:      "verify.dummy.token",
		ControllerSecret: storage.RandomHex(16),
		OwnProcessName:   "foxyvpn.exe",
	})
	if err != nil {
		fmt.Println("config build FAILED:", err)
		os.Exit(1)
	}

	libboxCheck(content)
	fmt.Println("ALL CHECKS PASSED")
}

func libboxCheck(content string) {
	// The fork requires a bearer token before parsing a dynamic outbound.
	libbox.SetBearerToken("verify.dummy.token")
	defer libbox.SetBearerToken("")
	if err := checkConfig(content); err != nil {
		fmt.Println("libbox.CheckConfig FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("libbox.CheckConfig OK")
}
