// Package tray implements the system tray icon with quick connect controls.
package tray

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/energye/systray"

	"foxyvpn/internal/model"
	"foxyvpn/internal/service"
)

type Tray struct {
	svc *service.Service
	// ShowWindow requests the main window to be brought to front.
	ShowWindow func()
	// Quit terminates the application.
	Quit func()

	statusItem  *systray.MenuItem
	connectItem *systray.MenuItem
	stopItem    *systray.MenuItem
	mu          sync.Mutex
	started     bool
}

func New(svc *service.Service, showWindow func(), quit func()) *Tray {
	return &Tray{svc: svc, ShowWindow: showWindow, Quit: quit}
}

// Start launches the tray loop on a locked OS thread.
func (t *Tray) Start(icon []byte) {
	if t.started {
		return
	}
	t.started = true
	go func() {
		runtime.LockOSThread()
		onReady := func() {
			systray.SetIcon(icon)
			systray.SetTitle("FoxyVPN")
			systray.SetTooltip("FoxyVPN — متصل نیستید")
			t.statusItem = systray.AddMenuItem("وضعیت: قطع", "وضعیت اتصال")
			t.statusItem.Disable()
			systray.AddSeparator()
			t.connectItem = systray.AddMenuItem("اتصال", "اتصال به سرور انتخابی")
			t.stopItem = systray.AddMenuItem("قطع", "قطع اتصال")
			t.stopItem.Disable()
			systray.AddSeparator()
			showItem := systray.AddMenuItem("نمایش پنجره", "باز کردن پنجره اصلی")
			systray.AddSeparator()
			quitItem := systray.AddMenuItem("خروج", "بستن FoxyVPN")

			t.connectItem.Click(func() { go t.svc.Connect() })
			t.stopItem.Click(func() { go t.svc.Disconnect() })
			showItem.Click(func() {
				if t.ShowWindow != nil {
					t.ShowWindow()
				}
			})
			quitItem.Click(func() {
				if t.Quit != nil {
					t.Quit()
				}
			})

			cancel := t.svc.Subscribe(func(snap service.Snapshot) {
				t.update(snap)
			})
			_ = cancel
			t.update(t.svc.Snapshot())
		}
		systray.Run(onReady, func() {})
	}()
}

func (t *Tray) update(snap service.Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.statusItem == nil {
		return
	}
	status := "وضعیت: قطع"
	tooltip := "FoxyVPN — متصل نیستید"
	switch snap.State {
	case model.Connecting.String():
		status = "وضعیت: در حال اتصال…"
		tooltip = "FoxyVPN — در حال اتصال…"
	case model.Connected.String():
		label := snap.Region
		if snap.ProxyOnly {
			status = fmt.Sprintf("وضعیت: پروکسی فعال (%s)", snap.SocksEndpoint)
		} else {
			status = fmt.Sprintf("وضعیت: متصل • %s", label)
		}
		tooltip = "FoxyVPN — متصل"
	}
	t.statusItem.SetTitle(status)
	t.statusItem.SetTooltip(status)
	systray.SetTooltip(tooltip)
	if snap.State == model.Connected.String() {
		t.connectItem.Disable()
		t.stopItem.Enable()
	} else {
		t.connectItem.Enable()
		t.stopItem.Disable()
	}
}
