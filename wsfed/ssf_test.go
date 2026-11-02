// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/rcbj/wsfed-caep-go/wsfed"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func b64urlTest(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func jwkOf(key *rsa.PrivateKey, kid string) map[string]any {
	n := key.N.Bytes()
	e := bigBytes(key.E)
	return map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": b64urlTest(n), "e": b64urlTest(e)}
}

func bigBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var raw []byte
	for n > 0 {
		raw = append([]byte{byte(n & 0xFF)}, raw...)
		n >>= 8
	}
	return raw
}

func signJWS(payload map[string]any, key *rsa.PrivateKey, header map[string]any) string {
	if header == nil {
		header = map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := b64urlTest(hb)
	p := b64urlTest(pb)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return h + "." + p + "." + b64urlTest(sig)
}

type ssfStub struct {
	queue   map[string]string
	acked   []string
	errs    map[string]any
	created int
	streams []map[string]any
	mu      sync.Mutex
	server  *httptest.Server
	jwk     map[string]any
	key     *rsa.PrivateKey
	other   *rsa.PrivateKey
}

func newStub(t *testing.T) *ssfStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stub := &ssfStub{queue: map[string]string{}, errs: map[string]any{}, key: key, other: other, jwk: jwkOf(key, "k1")}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readBody(r)
		path := r.URL.Path
		stub.mu.Lock()
		defer stub.mu.Unlock()
		switch {
		case path == "/.well-known/ssf-configuration":
			writeJSON(w, 200, map[string]any{
				"issuer": stub.server.URL, "jwks_uri": stub.server.URL + "/jwks",
				"configuration_endpoint":     stub.server.URL + "/ssf/stream",
				"verification_endpoint":      stub.server.URL + "/ssf/verify",
				"delivery_methods_supported": []string{"urn:ietf:rfc:8936"},
			})
		case path == "/jwks":
			writeJSON(w, 200, map[string]any{"keys": []any{stub.jwk}})
		case path == "/ssf/stream" && r.Method == "GET":
			writeJSON(w, 200, stub.streams)
		case path == "/ssf/stream" && r.Method == "POST":
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			stub.created++
			delivery, _ := parsed["delivery"].(map[string]any)
			stream := map[string]any{
				"stream_id": fmt.Sprintf("s%d", stub.created), "iss": stub.server.URL, "aud": "my-app",
				"delivery":         map[string]any{"method": delivery["method"], "endpoint_url": fmt.Sprintf("%s/ssf/poll/s%d", stub.server.URL, stub.created)},
				"events_requested": parsed["events_requested"],
				"events_delivered": parsed["events_requested"],
			}
			stub.streams = append(stub.streams, stream)
			writeJSON(w, 201, stream)
		case strings.HasPrefix(path, "/ssf/poll/"):
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			if ack, ok := parsed["ack"].([]any); ok {
				for _, item := range ack {
					jti := fmt.Sprint(item)
					stub.acked = append(stub.acked, jti)
					delete(stub.queue, jti)
				}
			}
			if errs, ok := parsed["setErrs"].(map[string]any); ok {
				for jti, errBody := range errs {
					stub.errs[jti] = errBody
					delete(stub.queue, jti)
				}
			}
			writeJSON(w, 200, map[string]any{"sets": stub.queue, "moreAvailable": false})
		default:
			writeJSON(w, 404, map[string]any{"err": "not found"})
		}
	}))
	t.Cleanup(stub.server.Close)
	return stub
}

func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	raw, _ := json.Marshal(body)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

type memLog struct{ errors []string }

func (m *memLog) Info(string)          {}
func (m *memLog) Warn(string)          {}
func (m *memLog) Error(message string) { m.errors = append(m.errors, message) }

func (s *ssfStub) put(eventType string, sub map[string]any, extra map[string]any, key *rsa.PrivateKey, aud, iss string) string {
	jti := b64urlTest(mustRand(16))
	if extra == nil {
		extra = map[string]any{}
	}
	extra["event_timestamp"] = 1
	if aud == "" {
		aud = "my-app"
	}
	if iss == "" {
		iss = s.server.URL
	}
	if key == nil {
		key = s.key
	}
	payload := map[string]any{"iss": iss, "aud": aud, "jti": jti, "iat": 1, "sub_id": sub, "events": map[string]any{eventType: extra}}
	s.mu.Lock()
	s.queue[jti] = signJWS(payload, key, nil)
	s.mu.Unlock()
	return jti
}

func mustRand(n int) []byte {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return buf
}

func loginOf(person, session string) *wsfed.Login {
	format := "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	return &wsfed.Login{
		NameID: person, Issuer: "x", Realm: "https://rp.test/", TrustVersion: "2005/02",
		NameIDFormat: &format, SessionIndex: &session,
		Attributes: map[string][]string{
			wsfed.DefaultSubjectAttribute:                                        {"urn:uuid:" + person},
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {person + "@example.com"},
		},
	}
}

func TestVerifiesASetAndRefusesTheWrongKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jwkOf(key, "k1")
	_, payload, err := wsfed.VerifyCompactJWS(signJWS(map[string]any{"a": 1}, key, nil), []map[string]any{jwk})
	if err != nil {
		t.Fatal(err)
	}
	if payload["a"] != float64(1) && payload["a"] != json.Number("1") {
		t.Fatal(payload)
	}
	_, _, err = wsfed.VerifyCompactJWS(signJWS(map[string]any{"a": 1}, other, nil), []map[string]any{jwk})
	rejects(t, err, "signature", "does not verify")
	_, _, err = wsfed.VerifyCompactJWS(signJWS(map[string]any{"a": 1}, key, map[string]any{"alg": "RS256", "kid": "nope"}), []map[string]any{jwk})
	rejects(t, err, "signature", "no RSA signing key with kid nope")
	_, _, err = wsfed.VerifyCompactJWS(signJWS(map[string]any{"a": 1}, key, map[string]any{"alg": "none"}), []map[string]any{jwk})
	rejects(t, err, "signature", "does not verify")
	_, _, err = wsfed.VerifyCompactJWS(signJWS(map[string]any{"a": 1}, key, map[string]any{"alg": "HS256", "kid": "k1"}), []map[string]any{jwk})
	rejects(t, err, "signature", "does not verify")
}

func TestSubjects(t *testing.T) {
	got := wsfed.SubjectOf(map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"}, "session": map[string]any{"format": "opaque", "id": "S1"}}, "https://i")
	if got["person"] != "urn:uuid:a" || got["idp_session"] != "S1" {
		t.Fatal(got)
	}
	if len(wsfed.SubjectOf(map[string]any{"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i")) != 0 {
		t.Fatal("foreign iss")
	}
	email := wsfed.SubjectOf(map[string]any{"format": "email", "email": "A@x.com"}, "https://i")
	if email["email"] != "A@x.com" {
		t.Fatal(email)
	}
}

func TestPollStreamEndsTheNamedSessions(t *testing.T) {
	stub := newStub(t)
	var ended [][]string
	var seen []*wsfed.SignalEvent
	receiver, err := wsfed.NewSignalsReceiver(stub.server.URL, func(ids []string, _ *wsfed.SignalEvent) error {
		ended = append(ended, append([]string{}, ids...))
		return nil
	}, &wsfed.ReceiverOptions{PollIntervalMs: 60000, Log: &memLog{}})
	if err != nil {
		t.Fatal(err)
	}
	receiver.On("*", func(event *wsfed.SignalEvent) error { seen = append(seen, event); return nil })
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
	if stub.created != 1 || strOf(receiver.Stream()["stream_id"]) != "s1" {
		t.Fatal(stub.created, receiver.Stream())
	}
	receiver.Track("L-a1", loginOf("alice", "IDP-A1"), nil)
	receiver.Track("L-a2", loginOf("alice", "IDP-A2"), nil)
	receiver.Track("L-b1", loginOf("bob", "IDP-B1"), nil)
	j1 := stub.put(wsfed.Event["session_revoked"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.server.URL, "sub": "urn:uuid:alice"}, "session": map[string]any{"format": "opaque", "id": "IDP-A1"}}, nil, nil, "", "")
	j2 := stub.put(wsfed.Event["credential_change"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.server.URL, "sub": "urn:uuid:bob"}}, map[string]any{"credential_type": "password", "change_type": "update"}, nil, "", "")
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if len(ended) != 1 || len(ended[0]) != 1 || ended[0][0] != "L-a1" {
		t.Fatal(ended)
	}
	var change *wsfed.SignalEvent
	for _, event := range seen {
		if event.JTI == j2 {
			change = event
		}
	}
	if change == nil || change.Ended || len(change.Sessions) != 1 || change.Sessions[0] != "L-b1" {
		t.Fatal(change)
	}
	j3 := stub.put(wsfed.Event["account_disabled"], map[string]any{"format": "iss_sub", "iss": stub.server.URL, "sub": "urn:uuid:alice"}, nil, nil, "", "")
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if len(ended) != 2 || ended[1][0] != "L-a2" {
		t.Fatal(ended)
	}
	if !has(stub.acked, j1) || !has(stub.acked, j2) {
		t.Fatal(stub.acked)
	}
	stub.put(wsfed.Event["credential_compromise"], map[string]any{"format": "email", "email": "BOB@example.com"}, map[string]any{"credential_type": "password"}, nil, "", "")
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if ended[2][0] != "L-b1" {
		t.Fatal(ended)
	}
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if !has(stub.acked, j3) {
		t.Fatal(stub.acked)
	}
	again, err := wsfed.NewSignalsReceiver(stub.server.URL, func([]string, *wsfed.SignalEvent) error { return nil }, &wsfed.ReceiverOptions{Log: &memLog{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	again.Stop()
	if stub.created != 1 || strOf(again.Stream()["stream_id"]) != "s1" {
		t.Fatal(stub.created, again.Stream())
	}
}

func strOf(value any) string {
	text, _ := value.(string)
	return text
}

func has(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func TestForgedSetsAreReported(t *testing.T) {
	stub := newStub(t)
	var ended [][]string
	index := wsfed.NewMemorySessionIndex(0)
	receiver, err := wsfed.NewSignalsReceiver(stub.server.URL, func(ids []string, _ *wsfed.SignalEvent) error {
		ended = append(ended, ids)
		return nil
	}, &wsfed.ReceiverOptions{Index: index, Log: &memLog{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
	receiver.Track("L-c1", loginOf("carol", "IDP-C1"), nil)
	subject := map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.server.URL, "sub": "urn:uuid:carol"}, "session": map[string]any{"format": "opaque", "id": "IDP-C1"}}
	forged := stub.put(wsfed.Event["session_revoked"], subject, nil, stub.other, "", "")
	mis := stub.put(wsfed.Event["session_revoked"], subject, nil, nil, "someone-else", "")
	foreign := stub.put(wsfed.Event["session_revoked"], subject, nil, nil, "", "https://evil.example")
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if len(ended) != 0 || strings.Join(index.ByPerson("urn:uuid:carol"), ",") != "L-c1" {
		t.Fatal(ended, index.ByPerson("urn:uuid:carol"))
	}
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	for _, jti := range []string{forged, mis, foreign} {
		if _, ok := stub.errs[jti]; !ok {
			t.Fatal(jti, stub.errs)
		}
	}
}

func TestEventCatalog(t *testing.T) {
	if len(wsfed.CAEPEvents) != 8 || len(wsfed.RISCEvents) != 14 {
		t.Fatal(len(wsfed.CAEPEvents), len(wsfed.RISCEvents))
	}
	if !has(wsfed.CAEPEvents, wsfed.Event["risk_level_change"]) || !has(wsfed.RISCEvents, wsfed.Event["opt_out_effective"]) {
		t.Fatal("catalog")
	}
}

func TestHandlerAndOnEndErrorsAreStillAcknowledged(t *testing.T) {
	stub := newStub(t)
	log := &memLog{}
	var seen []string
	receiver, err := wsfed.NewSignalsReceiver(stub.server.URL, func([]string, *wsfed.SignalEvent) error {
		return fmt.Errorf("store down")
	}, &wsfed.ReceiverOptions{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	receiver.On(wsfed.Event["credential_change"], func(*wsfed.SignalEvent) error { return fmt.Errorf("handler bug") })
	receiver.On("*", func(event *wsfed.SignalEvent) error { seen = append(seen, event.JTI); return nil })
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
	receiver.Track("L-d1", loginOf("dave", "IDP-D1"), nil)
	j1 := stub.put(wsfed.Event["credential_change"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.server.URL, "sub": "urn:uuid:dave"}}, map[string]any{"credential_type": "password", "change_type": "update"}, nil, "", "")
	j2 := stub.put(wsfed.Event["session_revoked"], map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": stub.server.URL, "sub": "urn:uuid:dave"}, "session": map[string]any{"format": "opaque", "id": "IDP-D1"}}, nil, nil, "", "")
	for i := 0; i < 3; i++ {
		if _, err := receiver.PollOnce(); err != nil {
			t.Fatal(err)
		}
	}
	if !has(stub.acked, j1) || !has(stub.acked, j2) {
		t.Fatal(stub.acked)
	}
	if _, ok := stub.errs[j1]; ok {
		t.Fatal(stub.errs)
	}
	if _, ok := stub.errs[j2]; ok {
		t.Fatal(stub.errs)
	}
	if !has(seen, j1) || !has(seen, j2) {
		t.Fatal(seen)
	}
	handler := false
	ended := false
	for _, message := range log.errors {
		if strings.Contains(message, "handler for") && strings.Contains(message, "credential-change") && strings.Contains(message, "threw") {
			handler = true
		}
		if strings.Contains(message, "onEndSessions threw") {
			ended = true
		}
	}
	if !handler || !ended {
		t.Fatal(log.errors)
	}
}

func TestOverlappingPollsHandleASetOnce(t *testing.T) {
	stub := newStub(t)
	var seen []string
	var mu sync.Mutex
	receiver, err := wsfed.NewSignalsReceiver(stub.server.URL, func([]string, *wsfed.SignalEvent) error { return nil }, &wsfed.ReceiverOptions{Log: &memLog{}})
	if err != nil {
		t.Fatal(err)
	}
	receiver.On("*", func(event *wsfed.SignalEvent) error {
		mu.Lock()
		seen = append(seen, event.JTI)
		mu.Unlock()
		return nil
	})
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
	jti := stub.put(wsfed.Event["account_enabled"], map[string]any{"format": "iss_sub", "iss": stub.server.URL, "sub": "urn:uuid:erin"}, nil, nil, "", "")
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = receiver.PollOnce()
		}()
	}
	wg.Wait()
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, item := range seen {
		if item == jti {
			count++
		}
	}
	if count != 1 {
		t.Fatal(seen)
	}
}

func TestRefusesATransmitterWithoutPollDelivery(t *testing.T) {
	receiver, err := wsfed.NewSignalsReceiver("http://127.0.0.1:1", func([]string, *wsfed.SignalEvent) error { return nil }, &wsfed.ReceiverOptions{Log: &memLog{}})
	if err != nil {
		t.Fatal(err)
	}
	err = receiver.Start()
	rejects(t, err, "ssf", "")
}
