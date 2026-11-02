// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// Package demo is the WS-Federation example application.
package demo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/rcbj/wsfed-caep-go/wsfed"
)

//go:embed public/styles.css
var stylesCSS []byte

var gifBytes []byte

func init() {
	gifBytes, _ = base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
}

// App is the request handler the example and the tests share. GET /live-status is JSON:
// signedIn, subject, receiver, and the accepted Shared Signals events (type and jti). It never
// includes tokens or assertions.
type App struct {
	RP            *wsfed.RelyingParty
	Receiver      *wsfed.SignalsReceiver
	mu            sync.Mutex
	sessions      map[string]*wsfed.Login
	events        [][2]string
	receiverState string
	secret        []byte
	replyPath     string
	secure        string
}

func New(rp *wsfed.RelyingParty, receiver *wsfed.SignalsReceiver) *App {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	reply, _ := url.Parse(rp.Config.ReplyURL)
	path := "/wsfed"
	if reply != nil && reply.Path != "" {
		path = reply.Path
	}
	secure := ""
	if reply != nil && reply.Scheme == "https" {
		secure = "; Secure"
	}
	return &App{RP: rp, Receiver: receiver, sessions: map[string]*wsfed.Login{}, receiverState: "not configured", secret: secret, replyPath: path, secure: secure}
}

func sign(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	encoded := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return value + "." + encoded
}

func unsign(secret []byte, signed string) string {
	if signed == "" || !strings.Contains(signed, ".") {
		return ""
	}
	value := signed[:strings.LastIndex(signed, ".")]
	if hmac.Equal([]byte(sign(secret, value)), []byte(signed)) {
		return value
	}
	return ""
}

func cookies(header string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(header, ";") {
		if !strings.Contains(part, "=") {
			continue
		}
		name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		if name != "" && value != "" {
			if _, ok := out[name]; !ok {
				out[name] = value
			}
		}
	}
	return out
}

func esc(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(value)
}

type header struct {
	Name  string
	Value string
}

// Drop forgets a local session, for example when a signal ends it.
func (a *App) Drop(id string) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
}

func (a *App) session(id string) *wsfed.Login {
	if id == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[id]
}

// SetReceiverState is what GET /live-status reports as receiver.
func (a *App) SetReceiverState(state string) {
	a.mu.Lock()
	a.receiverState = state
	a.mu.Unlock()
}

// Remember records an accepted Shared Signals event for GET /live-status.
func (a *App) Remember(event *wsfed.SignalEvent) {
	a.mu.Lock()
	a.events = append(a.events, [2]string{event.Type, event.JTI})
	// iya-sts main sets the WS-Federation assertion's SessionIndex to the
	// assertion id. The CAEP session-revoked subject names the sign-on
	// session instead, so the index finds nobody and the end callback is not
	// asked to drop this login. This demo has that one session.
	var ids []string
	if event.Type == wsfed.Event["session_revoked"] && len(event.Sessions) == 0 {
		for id := range a.sessions {
			ids = append(ids, id)
		}
		a.sessions = map[string]*wsfed.Login{}
	}
	receiver := a.Receiver
	a.mu.Unlock()
	if receiver != nil {
		for _, id := range ids {
			receiver.Untrack(id)
		}
	}
}

func (a *App) liveStatus(sid string) (int, []header, []byte) {
	who := a.session(sid)
	a.mu.Lock()
	events := make([]map[string]string, 0, len(a.events))
	for _, item := range a.events {
		events = append(events, map[string]string{"type": item[0], "jti": item[1]})
	}
	state := a.receiverState
	a.mu.Unlock()
	var subject any
	if who != nil {
		subject = who.NameID
	}
	body, _ := json.Marshal(map[string]any{
		"signedIn": who != nil,
		"subject":  subject,
		"receiver": state,
		"events":   events,
	})
	return 200, []header{{"content-type", "application/json"}, {"cache-control", "no-store"}}, body
}

func (a *App) pending(value string, age int) string {
	secure := a.secure
	if secure == "" {
		secure = "; Secure"
	}
	return fmt.Sprintf("wsfed_pending=%s; Path=%s; HttpOnly; SameSite=None%s; Max-Age=%d", value, a.replyPath, secure, age)
}

// Handle one request. Headers are lower-case names.
func (a *App) Handle(method, target string, headers map[string]string, body []byte) (int, []header, []byte) {
	parsed, _ := url.Parse(target)
	path := "/"
	if parsed != nil && parsed.Path != "" {
		path = parsed.Path
	}
	jar := cookies(headers["cookie"])
	sid := unsign(a.secret, jar["sid"])
	method = strings.ToUpper(method)
	if path == "/healthz" && method == "GET" {
		return 200, []header{{"content-type", "text/plain"}}, []byte("ok")
	}
	if path == "/live-status" && method == "GET" {
		return a.liveStatus(sid)
	}
	if path == "/login" && method == "GET" {
		request, err := a.RP.Login(&wsfed.LoginOptions{RelayState: strPtr("/")})
		if err != nil {
			return 500, []header{{"content-type", "text/plain"}}, []byte(err.Error())
		}
		return 302, []header{{"location", request.URL}, {"set-cookie", a.pending(sign(a.secret, request.ID), 600)}}, nil
	}
	if path == a.replyPath && a.RP.IsSignOutCleanup(wsfed.ReplyRequest{Method: method, URL: target}) {
		if sid != "" {
			a.Drop(sid)
			if a.Receiver != nil {
				a.Receiver.Untrack(sid)
			}
		}
		return 200, []header{{"content-type", "image/gif"}, {"set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + a.secure}}, gifBytes
	}
	if path == a.replyPath && method == "POST" {
		pending := unsign(a.secret, jar["wsfed_pending"])
		var ids []string
		if pending != "" {
			ids = []string{pending}
		}
		who, err := a.RP.HandleReply(wsfed.ReplyRequest{Method: "POST", URL: target, Body: string(body)}, ids)
		if err != nil {
			return 400, []header{{"content-type", "text/plain"}}, []byte("Sign-in failed.")
		}
		sessionID := tokenURL(24)
		a.mu.Lock()
		a.sessions[sessionID] = who
		a.mu.Unlock()
		if a.Receiver != nil {
			a.Receiver.Track(sessionID, who, nil)
		}
		next := "/"
		if who.RelayState != nil && strings.HasPrefix(*who.RelayState, "/") && !strings.HasPrefix(*who.RelayState, "//") {
			next = *who.RelayState
		}
		return 303, []header{
			{"location", next},
			{"set-cookie", a.pending("", 0)},
			{"set-cookie", fmt.Sprintf("sid=%s; Path=/; HttpOnly; SameSite=Lax%s", sign(a.secret, sessionID), a.secure)},
		}, nil
	}
	if path == "/logout" && method == "POST" {
		if sid != "" {
			a.Drop(sid)
			if a.Receiver != nil {
				a.Receiver.Untrack(sid)
			}
		}
		replyURL, _ := url.Parse(a.RP.Config.ReplyURL)
		origin := "/"
		if replyURL != nil {
			origin = replyURL.Scheme + "://" + replyURL.Host + "/"
		}
		location, err := a.RP.Logout(origin)
		if err != nil {
			return 500, []header{{"content-type", "text/plain"}}, []byte(err.Error())
		}
		return 303, []header{{"location", location}, {"set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + a.secure}}, nil
	}
	if path == "/FederationMetadata/2007-06/FederationMetadata.xml" && method == "GET" {
		return 200, []header{{"content-type", "application/samlmetadata+xml"}}, []byte(a.RP.Metadata())
	}
	if path == "/" && method == "GET" {
		who := a.session(sid)
		page := `<p><a href="/login">Sign in with WS-Federation</a></p>`
		if who != nil {
			page = "<p>Signed in as <strong>" + esc(who.NameID) + "</strong> by " + esc(who.Issuer) + ".</p>" +
				`<form method="post" action="/logout"><button>Sign out</button></form>`
		}
		html := `<!DOCTYPE html><html><head><meta charset="utf-8"><title>WS-Federation</title><link rel="stylesheet" href="/styles.css"></head><body><main>` + page + `</main></body></html>`
		return 200, []header{{"content-type", "text/html; charset=utf-8"}}, []byte(html)
	}
	if path == "/styles.css" && method == "GET" {
		body := stylesCSS
		if len(body) == 0 {
			body = []byte("body{font-family:sans-serif}\n")
		}
		return 200, []header{{"content-type", "text/css"}}, body
	}
	return 404, []header{{"content-type", "text/plain"}}, []byte("Not found")
}

func strPtr(value string) *string { return &value }

func tokenURL(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Serve answers GET /healthz before the identity provider is reachable.
func Serve(port int, getApp func() (*App, error)) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("content-type", "text/plain")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
			return
		}
		app, err := getApp()
		if err != nil {
			w.Header().Set("content-type", "text/plain")
			w.WriteHeader(503)
			_, _ = io.WriteString(w, "not ready: "+err.Error()+"\n")
			return
		}
		body, _ := io.ReadAll(r.Body)
		headers := map[string]string{}
		for name, values := range r.Header {
			if len(values) > 0 {
				headers[strings.ToLower(name)] = values[0]
			}
		}
		status, fields, payload := app.Handle(r.Method, r.URL.RequestURI(), headers, body)
		for _, field := range fields {
			w.Header().Add(field.Name, field.Value)
		}
		w.Header().Set("content-length", fmt.Sprintf("%d", len(payload)))
		w.WriteHeader(status)
		_, _ = w.Write(payload)
	})
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	fmt.Printf("wsfed-caep demo on port %d\n", port)
	return http.Serve(ln, mux)
}

func publicURL(argv []string) (string, bool, error) {
	given := os.Getenv("PUBLIC_URL") != ""
	public := strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--public-url" {
			if i+1 >= len(argv) || argv[i+1] == "" {
				return "", false, fmt.Errorf("--public-url is empty")
			}
			public = strings.TrimRight(argv[i+1], "/")
			given = true
			i++
		}
	}
	return public, given, nil
}

func configPath(argv []string) string {
	configured := os.Getenv("WSFED_CONFIG")
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--config" && i+1 < len(argv) {
			configured = argv[i+1]
		}
	}
	if configured == "" {
		return "demo/wsfed.json"
	}
	return configured
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func onPort(raw string, port int) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || !loopback(parsed.Hostname()) {
		return raw
	}
	host := parsed.Hostname()
	if strings.Contains(host, ":") {
		parsed.Host = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		parsed.Host = fmt.Sprintf("%s:%d", host, port)
	}
	return parsed.String()
}

func moveOrigin(value, public string) string {
	base, err := url.Parse(public)
	if err != nil {
		return value
	}
	if !strings.HasSuffix(public, "/") {
		base, _ = url.Parse(public + "/")
	}
	next, err := url.Parse(value)
	if err != nil || base == nil {
		return value
	}
	host := base.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if base.Port() != "" {
		host = host + ":" + base.Port()
	}
	next.Scheme = base.Scheme
	next.Host = host
	return next.String()
}

// EndpointsFor rewrites a loopback realm and reply URL onto port, or onto an explicit public origin.
func EndpointsFor(realm, reply, public string, given bool, port int) (string, string) {
	if given && public != "" {
		return moveOrigin(realm, public), moveOrigin(reply, public)
	}
	if port > 0 {
		return onPort(realm, port), onPort(reply, port)
	}
	return realm, reply
}

// Main runs the demo HTTP server.
func Main(argv []string) int {
	port := 3000
	if text := os.Getenv("PORT"); text != "" {
		if n, err := strconv.Atoi(text); err == nil {
			port = n
		}
	}
	for i, arg := range argv {
		if arg == "--port" && i+1 < len(argv) {
			if n, err := strconv.Atoi(argv[i+1]); err == nil {
				port = n
			}
		}
	}
	public, given, err := publicURL(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	path := configPath(argv)
	var holder *App
	err = Serve(port, func() (*App, error) {
		if holder != nil {
			return holder, nil
		}
		party, raw, err := LoadParty(path, port, public, given)
		if err != nil {
			return nil, err
		}
		app := New(party, nil)
		ssfBlock, _ := raw["ssf"].(map[string]any)
		transmitterOf, _ := ssfBlock["transmitter"].(string)
		switch {
		case raw["signals"] == false:
			app.SetReceiverState("not configured (signals are off)")
		case transmitterOf == "":
			app.SetReceiverState("not configured (no ssf block in the configuration file)")
		case party.Config.PrivateKey == nil:
			app.SetReceiverState("not running: the relying party has no private key")
		}
		if raw["signals"] != false {
			if ssf := ssfBlock; ssf != nil {
				transmitter, _ := ssf["transmitter"].(string)
				if transmitter != "" && party.Config.PrivateKey != nil {
					interval := 5000
					switch n := ssf["pollIntervalMs"].(type) {
					case float64:
						if n > 0 {
							interval = int(n)
						}
					}
					tls := &wsfed.TLSConfig{CA: party.Config.IdPCA}
					if party.Config.Certificate != nil {
						tls.Cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: party.Config.Certificate.Raw}))
					}
					if pkcs8, err := x509.MarshalPKCS8PrivateKey(party.Config.PrivateKey); err == nil {
						tls.Key = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
					}
					receiver, err := wsfed.NewSignalsReceiver(transmitter, func(ids []string, _ *wsfed.SignalEvent) error {
						for _, id := range ids {
							app.Drop(id)
						}
						return nil
					}, &wsfed.ReceiverOptions{TLS: tls, PollIntervalMs: interval})
					if err != nil {
						app.SetReceiverState("not running: " + err.Error())
						fmt.Printf("ssf: not started: %s\n", err.Error())
					} else {
						receiver.On("*", func(event *wsfed.SignalEvent) error {
							app.Remember(event)
							return nil
						})
						app.mu.Lock()
						app.Receiver = receiver
						app.mu.Unlock()
						if err := receiver.Start(); err != nil {
							app.mu.Lock()
							app.Receiver = nil
							app.mu.Unlock()
							app.SetReceiverState("not running: " + err.Error())
							fmt.Printf("ssf: not started: %s\n", err.Error())
						} else {
							streamID, _ := receiver.Stream()["stream_id"].(string)
							app.SetReceiverState("polling stream " + streamID + " at " + transmitter)
						}
					}
				}
			}
		}
		holder = app
		return app, nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	return 0
}

// LoadParty reads the configuration and follows PORT or PUBLIC_URL.
func LoadParty(path string, port int, public string, given bool) (*wsfed.RelyingParty, map[string]any, error) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return nil, nil, err
	}
	realm, _ := raw["realm"].(string)
	reply, _ := raw["replyUrl"].(string)
	realm, reply = EndpointsFor(realm, reply, public, given, port)
	overrides := map[string]any{}
	if realm != "" {
		overrides["realm"] = realm
	}
	if reply != "" {
		overrides["replyUrl"] = reply
	}
	party, err := wsfed.FromFile(path, overrides)
	if err != nil {
		return nil, raw, err
	}
	return party, raw, nil
}
