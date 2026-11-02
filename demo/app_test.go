// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package demo

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rcbj/wsfed-caep-go/stubidp"
	"github.com/rcbj/wsfed-caep-go/wsfed"
)

func TestSignInCleanupAndLogout(t *testing.T) {
	rp, err := wsfed.Create(map[string]any{
		"realm": "https://rp.test/", "replyUrl": "https://rp.test/wsfed",
		"privateKey": stubidp.RPKey, "certificate": stubidp.RPCert,
		"idpMetadata": stubidp.IdPMetadata(nil),
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := New(rp, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			w.WriteHeader(status)
			_, _ = w.Write(payload)
		}))
	}()
	t.Cleanup(func() { _ = ln.Close() })
	base := "http://127.0.0.1:" + itoa(port)
	res, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	health, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(health) != "ok" {
		t.Fatal(res.StatusCode, string(health))
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	login, err := client.Get(base + "/login")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(login.Body)
	login.Body.Close()
	if login.StatusCode != 302 {
		t.Fatal(login.StatusCode)
	}
	parsed, _ := url.Parse(login.Header.Get("location"))
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != stubidp.Passive {
		t.Fatal(login.Header.Get("location"))
	}
	params := parsed.Query()
	if params.Get("wa") != "wsignin1.0" {
		t.Fatal(params)
	}
	pending := cookieValue(login, "wsfed_pending")
	made, err := stubidp.SignedAssertion(nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := stubidp.WResult(&stubidp.WResultOptions{Token: &made.XML})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"wa": {"wsignin1.0"}, "wresult": {result}, "wctx": {params.Get("wctx")}}
	req, _ := http.NewRequest("POST", base+"/wsfed", strings.NewReader(form.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("cookie", "wsfed_pending="+pending)
	reply, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := io.ReadAll(reply.Body)
	reply.Body.Close()
	if reply.StatusCode != 303 {
		t.Fatal(reply.StatusCode, string(msg))
	}
	sid := cookieValue(reply, "sid")
	statusReq, _ := http.NewRequest("GET", base+"/live-status", nil)
	statusReq.Header.Set("cookie", "sid="+sid)
	statusRes, err := client.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	statusBody, _ := io.ReadAll(statusRes.Body)
	statusRes.Body.Close()
	if statusRes.StatusCode != 200 || statusRes.Header.Get("cache-control") != "no-store" {
		t.Fatal(statusRes.StatusCode, statusRes.Header)
	}
	var live map[string]any
	if err := json.Unmarshal(statusBody, &live); err != nil {
		t.Fatal(err)
	}
	if live["signedIn"] != true || live["subject"] != "alice-1234" || live["receiver"] != "not configured" {
		t.Fatal(string(statusBody))
	}
	if events, ok := live["events"].([]any); !ok || len(events) != 0 {
		t.Fatal(string(statusBody))
	}
	if strings.Contains(string(statusBody), "Assertion") || strings.Contains(string(statusBody), "wresult") {
		t.Fatal(string(statusBody))
	}
	homeReq, _ := http.NewRequest("GET", base+"/", nil)
	homeReq.Header.Set("cookie", "sid="+sid)
	home, err := client.Do(homeReq)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(home.Body)
	home.Body.Close()
	if !strings.Contains(string(page), "Signed in as <strong>alice-1234</strong>") || !strings.Contains(string(page), stubidp.IdPEntity) {
		t.Fatal(string(page))
	}
	cleanReq, _ := http.NewRequest("GET", base+"/wsfed?wa=wsignoutcleanup1.0", nil)
	cleanReq.Header.Set("cookie", "sid="+sid)
	cleanup, err := client.Do(cleanReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(cleanup.Body)
	cleanup.Body.Close()
	if cleanup.Header.Get("content-type") != "image/gif" {
		t.Fatal(cleanup.Header.Get("content-type"))
	}
	homeReq, _ = http.NewRequest("GET", base+"/", nil)
	homeReq.Header.Set("cookie", "sid="+sid)
	home, _ = client.Do(homeReq)
	page, _ = io.ReadAll(home.Body)
	home.Body.Close()
	if !strings.Contains(string(page), "Sign in with WS-Federation") {
		t.Fatal(string(page))
	}
	outReq, _ := http.NewRequest("POST", base+"/logout", nil)
	out, err := client.Do(outReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(out.Body)
	out.Body.Close()
	loc, _ := url.Parse(out.Header.Get("location"))
	if loc.Query().Get("wa") != "wsignout1.0" {
		t.Fatal(out.Header.Get("location"))
	}
	bad, _ := http.NewRequest("POST", base+"/wsfed", strings.NewReader("wa=wsignin1.0&wresult=x&wctx=id%3Dabc"))
	bad.Header.Set("content-type", "application/x-www-form-urlencoded")
	refused, err := client.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(refused.Body)
	refused.Body.Close()
	if refused.StatusCode != 400 {
		t.Fatal(refused.StatusCode)
	}
}

func TestLiveStatusRecordsEventsAndSessionRevokedEndsTheOneSession(t *testing.T) {
	rp, err := wsfed.Create(map[string]any{
		"realm": "https://rp.test/", "replyUrl": "https://rp.test/wsfed",
		"privateKey": stubidp.RPKey, "certificate": stubidp.RPCert,
		"idpMetadata": stubidp.IdPMetadata(nil),
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := New(rp, nil)
	_, fields, _ := app.Handle("GET", "/login", map[string]string{}, nil)
	var location, pending string
	for _, field := range fields {
		if field.Name == "location" {
			location = field.Value
		}
		if field.Name == "set-cookie" && strings.HasPrefix(field.Value, "wsfed_pending=") {
			pending = strings.TrimPrefix(strings.Split(field.Value, ";")[0], "wsfed_pending=")
		}
	}
	parsed, _ := url.Parse(location)
	made, err := stubidp.SignedAssertion(nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := stubidp.WResult(&stubidp.WResultOptions{Token: &made.XML})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"wa": {"wsignin1.0"}, "wresult": {result}, "wctx": {parsed.Query().Get("wctx")}}
	status, fields, msg := app.Handle("POST", "/wsfed", map[string]string{"cookie": "wsfed_pending=" + pending}, []byte(form.Encode()))
	if status != 303 {
		t.Fatal(status, string(msg))
	}
	var sid string
	for _, field := range fields {
		if field.Name == "set-cookie" && strings.HasPrefix(field.Value, "sid=") {
			sid = strings.TrimPrefix(strings.Split(field.Value, ";")[0], "sid=")
		}
	}
	live := func() map[string]any {
		_, _, body := app.Handle("GET", "/live-status", map[string]string{"cookie": "sid=" + sid}, nil)
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	app.Remember(&wsfed.SignalEvent{Type: wsfed.Event["credential_change"], JTI: "jti-1"})
	got := live()
	if got["signedIn"] != true {
		t.Fatal(got)
	}
	events := got["events"].([]any)
	if len(events) != 1 || events[0].(map[string]any)["type"] != wsfed.Event["credential_change"] || events[0].(map[string]any)["jti"] != "jti-1" {
		t.Fatal(got)
	}
	app.Remember(&wsfed.SignalEvent{Type: wsfed.Event["session_revoked"], JTI: "jti-2"})
	got = live()
	if got["signedIn"] != false || got["subject"] != nil {
		t.Fatal(got)
	}
	events = got["events"].([]any)
	if len(events) != 2 || events[1].(map[string]any)["type"] != wsfed.Event["session_revoked"] || events[1].(map[string]any)["jti"] != "jti-2" {
		t.Fatal(got)
	}
}

func cookieValue(res *http.Response, name string) string {
	for _, raw := range res.Header.Values("set-cookie") {
		pair := strings.Split(raw, ";")[0]
		if key, value, ok := strings.Cut(pair, "="); ok && key == name {
			return value
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
