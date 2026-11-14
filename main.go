package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"foxyvpn/internal/logx"
	"foxyvpn/internal/remoteconfig"
	"foxyvpn/internal/service"
	"foxyvpn/internal/settings"
	"foxyvpn/internal/storage"
	"foxyvpn/internal/tray"
	"foxyvpn/internal/winutil"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed assets/icon.ico
var trayIcon []byte

//go:embed assets/wintun.dll
var wintunDll []byte

func main() {
	if !winutil.AcquireSingleInstance() {
		// Another instance is running: bring its window to the front
		// instead of starting a second copy.
		winutil.NotifyRunningInstance()
		return
	}
	defer winutil.ReleaseSingleInstance()

	// pin the main window webview to a direct connection: applying the system
// proxy must not kill the GUI process.
	_ = os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
		"--proxy-server=direct:// --proxy-bypass-list=<-loopback>")

	if err := winutil.EnsureWintunDll(wintunDll); err != nil {
		fmt.Fprintln(os.Stderr, "wintun.dll:", err)
	}

	remoteconfig.Init()

	cfg, err := settings.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "settings:", err)
		return
	}
	creds, err := storage.LoadCredentials()
	if err != nil {
		logx.WarnErr("App", err)
		creds = &storage.CredentialsStore{}
	}
	tokens := storage.NewTokenStore()

	svc := service.New(cfg, creds, tokens)
	app := NewApp(cfg, creds, tokens, svc)
	app.tray = tray.New(svc,
		func() { app.showWindow() },
		func() { app.quitFromTray() },
	)

	err = wails.Run(&options.App{
		Title:            "FoxyVPN",
		Width:            460,
		Height:           780,
		MinWidth:         400,
		MinHeight:        660,
		DisableResize:    false,
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.Startup,
		OnShutdown:       app.Shutdown,
		OnBeforeClose:    app.BeforeClose,
		Bind:             []interface{}{app},
		StartHidden:      false,
		HideWindowOnClose: false,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
