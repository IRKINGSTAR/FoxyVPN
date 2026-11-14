// In-memory log buffer with secret redaction.
package logx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"foxyvpn/internal/settings"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	}
	return "?"
}

type Entry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Tag     string    `json:"tag"`
	Message string    `json:"message"`
}

const maxEntries = 2000

var (
	mu       sync.Mutex
	entries  []Entry
	watchers []chan []Entry
)

// secret redaction patterns.
var (
	accessTokenRe  = regexp.MustCompile(`(?i)(access_token[":=\s]+)[A-Za-z0-9_\-\.]+`)
	refreshTokenRe = regexp.MustCompile(`(?i)(refresh_token[":=\s]+)[A-Za-z0-9_\-\.]+`)
	sessionTokenRe = regexp.MustCompile(`(?i)(session[_ ]?token[":=\s]+)[A-Za-z0-9_\-\.]+`)
	bearerRe       = regexp.MustCompile(`(?i)(bearer[":=\s]+)[A-Za-z0-9_\-\.]+`)
	passwordRe     = regexp.MustCompile(`(?i)(password[":=\s]+)\S+`)
	authorizationRe = regexp.MustCompile(`(?i)(authorization[":=\s]+)\S+`)
	hawkRe         = regexp.MustCompile(`Hawk id="[^"]+"`)
	tokenFieldRe   = regexp.MustCompile(`("token"[":=\s]+)[A-Za-z0-9_\-\.]+`)
)

func Redact(message string) string {
	message = accessTokenRe.ReplaceAllString(message, `${1}<redacted>`)
	message = refreshTokenRe.ReplaceAllString(message, `${1}<redacted>`)
	message = sessionTokenRe.ReplaceAllString(message, `${1}<redacted>`)
	message = bearerRe.ReplaceAllString(message, `${1}<redacted>`)
	message = passwordRe.ReplaceAllString(message, `${1}<redacted>`)
	message = authorizationRe.ReplaceAllString(message, `${1}<redacted>`)
	message = hawkRe.ReplaceAllString(message, `Hawk id="<redacted>"`)
	message = tokenFieldRe.ReplaceAllString(message, `${1}<redacted>`)
	return message
}

func publish(level Level, tag, message string) {
	e := Entry{Time: time.Now(), Level: level.String(), Tag: tag, Message: Redact(message)}
	mu.Lock()
	entries = append(entries, e)
	if len(entries) > maxEntries {
		entries = entries[len(entries)-maxEntries:]
	}
	subs := make([]chan []Entry, len(watchers))
	copy(subs, watchers)
	mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- []Entry{e}:
		default:
		}
	}
	if level >= LevelError {
		appendCrashFile(e)
	}
}

// appendCrashFile persists ERROR entries to disk so silent crashes (GUI
// subsystem has no stderr) can be diagnosed afterwards. Best-effort only.
func appendCrashFile(e Entry) {
	defer func() { _ = recover() }()
	dir := settings.AppDataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, "foxyvpn-error.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 512*1024 {
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s %s: %s\n", e.Time.Format(time.RFC3339), e.Level, e.Tag, e.Message)
}

func Debug(tag, format string, args ...any)  { publish(LevelDebug, tag, fmt.Sprintf(format, args...)) }
func Info(tag, format string, args ...any)   { publish(LevelInfo, tag, fmt.Sprintf(format, args...)) }
func Warn(tag, format string, args ...any)   { publish(LevelWarn, tag, fmt.Sprintf(format, args...)) }
func Error(tag, format string, args ...any)  { publish(LevelError, tag, fmt.Sprintf(format, args...)) }
func WarnErr(tag string, err error)          { publish(LevelWarn, tag, withCause(err)) }
func ErrorErr(tag string, err error)         { publish(LevelError, tag, withCause(err)) }

func withCause(err error) string {
	if err == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(err.Error())
	type unwrapper interface{ Unwrap() error }
	for e := err; ; {
		u, ok := e.(unwrapper)
		if !ok {
			break
		}
		next := u.Unwrap()
		if next == nil {
			break
		}
		b.WriteString(": ")
		b.WriteString(next.Error())
		e = next
	}
	return b.String()
}

func Entries() []Entry {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Entry, len(entries))
	copy(out, entries)
	return out
}

func Clear() {
	mu.Lock()
	entries = nil
	mu.Unlock()
}

// Subscribe returns a channel receiving new entries. The returned cancel
// function must be called to stop delivery.
func Subscribe(buffer int) (ch <-chan []Entry, cancel func()) {
	c := make(chan []Entry, buffer)
	mu.Lock()
	watchers = append(watchers, c)
	idx := len(watchers) - 1
	mu.Unlock()
	return c, func() {
		mu.Lock()
		watchers[idx] = nil
		watchers = append(watchers[:idx], watchers[idx+1:]...)
		mu.Unlock()
	}
}
