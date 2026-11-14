package login

import (
	"encoding/json"
	"regexp"
	"strings"
)

var sessionTokenHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func hostOf(href string) string {
	h := href
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

func endsWith(s, suffix string) bool {
	return strings.HasSuffix(s, suffix)
}

// raw postMessage payload.
type bridgePayload struct {
	Foxy string `json:"foxy"`
	Href string `json:"href"`
}

// WebChannel message envelope.
type envelope struct {
	ID      string `json:"id"`
	Message struct {
		MessageID string          `json:"messageId"`
		Command   string          `json:"command"`
		Data      json.RawMessage `json:"data"`
	} `json:"message"`
}

// parseEnvelope decodes the raw WebChannel envelope delivered by the hook.
func parseEnvelope(raw string) (envelope, bool) {
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return envelope{}, false
	}
	if env.Message.Command == "" {
		return envelope{}, false
	}
	return env, true
}

// reply answers a WebChannel command through the injected hook.
func reply(eval func(string), channelID, messageID, command, dataJSON string) {
	q := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	script := "window.__foxyReply && window.__foxyReply(" +
		q(channelID) + ", " + q(messageID) + ", " + q(command) + ", " + dataJSON + ");"
	eval(script)
}

// trustedOrigin checks the page host that delivered the message. Unlike the
// Android version, the host is derived from the actual page URL the WebView
// reported (hardened against the caller-supplied-origin weakness).
func trustedOrigin(href string) bool {
	host := hostOf(href)
	return host == "accounts.firefox.com" || endsWith(host, ".firefox.com")
}

// handleEnvelope processes one WebChannel message.
func handleEnvelope(env envelope, href string, eval func(string), notify func(token, href string)) {
	if !trustedOrigin(href) {
		return
	}
	command := env.Message.Command
	messageID := env.Message.MessageID
	channelID := env.ID
	if channelID == "" {
		channelID = fxaChannelID
	}
	switch command {
	case cmdFxaStatus:
		reply(eval, channelID, messageID, cmdFxaStatus, `{"capabilities":{},"signedInUser":null}`)
	case cmdCanLinkAccount:
		reply(eval, channelID, messageID, cmdCanLinkAccount, `{"ok":true}`)
	case cmdLogin, "fxaccounts:oauth_login":
		var data struct {
			SessionToken string `json:"sessionToken"`
			Token        string `json:"token"`
		}
		if len(env.Message.Data) > 0 {
			_ = json.Unmarshal(env.Message.Data, &data)
		}
		token := strings.TrimSpace(data.SessionToken)
		if token == "" {
			token = strings.TrimSpace(data.Token)
		}
		clean := cleanHex(token)
		if sessionTokenHexRe.MatchString(clean) {
			notify(clean, href)
		}
		if messageID != "" {
			reply(eval, channelID, messageID, command, `{"ok":true}`)
		}
	default:
		if messageID != "" {
			reply(eval, channelID, messageID, command, `{"ok":true}`)
		}
	}
}

func cleanHex(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case ' ', '\t', '\n', '\r', '"':
			continue
		}
		if c >= 'A' && c <= 'F' {
			c = c + 32
		}
		b.WriteRune(c)
	}
	return b.String()
}
