// FxA login window on WebView2 (WebChannel flow).
package login

import (
	"runtime"
	"sync"

	"github.com/jchv/go-webview2"

	"foxyvpn/internal/logx"
)

const tag = "LoginWindow"

const fxaChannelID = "account_updates"

const cmdFxaStatus = "fxaccounts:fxa_status"
const cmdCanLinkAccount = "fxaccounts:can_link_account"
const cmdLogin = "fxaccounts:login"

// hook injected into the login page: forwards WebChannelMessageToChrome
// events to window.foxyWebChannel (provided via Bind).
const webchannelHookJS = `
(function() {
  if (window.__foxyChannelHooked) return;
  window.__foxyChannelHooked = true;
  var send = function(o) {
    try {
      var host = window.location.hostname;
      if (host !== 'accounts.firefox.com' && !host.endsWith('.firefox.com')) return;
      var payload = typeof o === 'string' ? o : JSON.stringify(o);
      window.foxyWebChannel(payload, window.location.href);
    } catch (e) {}
  };
  var onChannel = function(e) {
    var d = e.detail;
    if (typeof d === 'string') { try { d = JSON.parse(d); } catch (e2) { return; } }
    if (d && d.message) send(d);
  };
  window.addEventListener('WebChannelMessageToChrome', onChannel);
  document.addEventListener('WebChannelMessageToChrome', onChannel);
  window.__foxyReply = function(id, messageId, command, data) {
    var detail = { id: id, message: { messageId: messageId, command: command, data: data } };
    window.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail }));
    document.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail }));
  };
})();
`

// Options configures the login window.
type Options struct {
	StartURL string
	// OnSessionToken receives a validated 64-hex FxA session token
	// (called from a helper goroutine). The window closes automatically
	// once a token is captured.
	OnSessionToken func(token string)
	// OnClosed is called when the window closes (from the window thread).
	OnClosed func()
}

// Run opens the WebView2 login window and blocks until it closes.
//
// the message loop must stay pinned to one OS thread
func Run(opts Options) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() {
		if r := recover(); r != nil {
			logx.Error(tag, "login window panic: %v", r)
		}
	}()

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "FoxyVPN — Sign in with Firefox",
			Width:  430,
			Height: 660,
			Center: true,
		},
	})
	if w == nil {
		logx.Error(tag, "could not create the WebView2 login window")
		if opts.OnClosed != nil {
			opts.OnClosed()
		}
		return
	}
	defer w.Destroy()

	var (
		lastToken   string
		tokenMu     sync.Mutex
		windowOpen  = true
		windowMu    sync.Mutex
	)

	closeWindow := func() {
		windowMu.Lock()
		open := windowOpen
		windowOpen = false
		windowMu.Unlock()
		if open {
			w.Destroy() // posts WM_CLOSE; Run() returns afterwards
		}
	}

	notify := func(token, href string) {
		if !trustedOrigin(href) {
			return
		}
		tokenMu.Lock()
		if token == lastToken {
			tokenMu.Unlock()
			return
		}
		lastToken = token
		tokenMu.Unlock()
		logx.Info(tag, "captured an FxA session token from the login page")
		// close the window now; the exchange continues in the background
		closeWindow()
		if opts.OnSessionToken != nil {
			// Must stay fast and synchronous: we are on the UI thread inside
			// a COM event handler. The caller only queues the token.
			opts.OnSessionToken(token)
		}
	}

	// replies must be queued; Eval inside the COM handler would re-enter it
	eval := func(script string) {
		w.Dispatch(func() { w.Eval(script) })
	}

	// window.foxyWebChannel is provided via Bind; guard against panics
	_ = w.Bind("foxyWebChannel", func(payload string, href string) {
		defer func() {
			if r := recover(); r != nil {
				logx.Error(tag, "webchannel handler panic: %v", r)
			}
		}()
		env, ok := parseEnvelope(payload)
		if !ok {
			return
		}
		handleEnvelope(env, href, eval, notify)
	})

	w.Init(webchannelHookJS)
	w.Navigate(opts.StartURL)
	w.Run()

	windowMu.Lock()
	windowOpen = false
	windowMu.Unlock()
	logx.Info(tag, "login window closed")
	if opts.OnClosed != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logx.Error(tag, "onClosed panic: %v", r)
				}
			}()
		opts.OnClosed()
	}()
}

}
