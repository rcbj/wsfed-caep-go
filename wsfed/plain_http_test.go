// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rcbj/wsfed-caep-go/stubidp"
	"github.com/rcbj/wsfed-caep-go/wsfed"
)

// Plain http is refused off loopback for every fetch (#7): the federation
// metadata URL and the Shared Signals transmitter, before any connection, and
// the refusal names only the scheme and host.

const plainRefused = "is refused: plain http is allowed only to a loopback host"

type quietLog struct{}

func (quietLog) Info(string)  {}
func (quietLog) Warn(string)  {}
func (quietLog) Error(string) {}

// plainStub answers /md with the stub IdP's metadata, /away with a 302 to
// http://example.com/md and anything else with 404, counting every request.
func plainStub(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	metadata := stubidp.IdPMetadata(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/md":
			w.Header().Set("content-type", "application/samlmetadata+xml")
			_, _ = w.Write([]byte(metadata))
		case "/away":
			w.Header().Set("location", "http://example.com/md")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, hits
}

func partyAt(metadataURL string) error {
	_, err := wsfed.Create(map[string]any{
		"realm":       stubidp.Realm,
		"replyUrl":    stubidp.Reply,
		"privateKey":  stubidp.RPKey,
		"certificate": stubidp.RPCert,
		"idpMetadata": metadataURL,
	}, "")
	return err
}

func receiverAt(transmitter string) error {
	receiver, err := wsfed.NewSignalsReceiver(transmitter, func([]string, *wsfed.SignalEvent) error { return nil }, &wsfed.ReceiverOptions{Log: quietLog{}})
	if err != nil {
		return err
	}
	err = receiver.Start()
	receiver.Stop()
	return err
}

func refusedAs(t *testing.T, err error, code, shown string) *wsfed.WsFedError {
	t.Helper()
	var ws *wsfed.WsFedError
	if !errors.As(err, &ws) {
		t.Fatalf("not refused: %v", err)
	}
	if ws.Code != code {
		t.Fatalf("code %q, want %q: %s", ws.Code, code, ws.Message)
	}
	if !strings.HasPrefix(ws.Message, shown+" "+plainRefused) {
		t.Fatalf("message %q does not start with %q", ws.Message, shown)
	}
	for _, part := range []string{"s3cret", "/md", "/ssf", "federationmetadata", "token="} {
		if strings.Contains(ws.Message, part) {
			t.Fatalf("message %q carries %q", ws.Message, part)
		}
	}
	return ws
}

func TestPlainHTTPMetadataOffLoopbackIsRefused(t *testing.T) {
	refusedAs(t, partyAt("http://example.com/federationmetadata.xml?token=s3cret"), "metadata", "http://example.com")
}

func TestPlainHTTPTransmitterOffLoopbackIsRefused(t *testing.T) {
	refusedAs(t, receiverAt("http://example.com/ssf"), "ssf", "http://example.com")
}

func TestPlainHTTPIsRefusedBeforeConnecting(t *testing.T) {
	// On Linux http://0.0.0.0:<port> reaches a listener on 127.0.0.1, so no
	// accepted connection after the refusals shows none was opened.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	plain := "http://0.0.0.0:" + port
	refusedAs(t, partyAt(plain+"/md"), "metadata", plain)
	refusedAs(t, receiverAt(plain), "ssf", plain)
	time.Sleep(300 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("a refused fetch opened %d connection(s)", n)
	}
}

func TestUserinfoIsNeverLoopbackAndNeverShown(t *testing.T) {
	server, hits := plainStub(t)
	origin := strings.TrimPrefix(server.URL, "http://")
	ws := refusedAs(t, partyAt("http://alice:s3cret@"+origin+"/md"), "metadata", "http://"+origin)
	if strings.Contains(ws.Message, "alice") {
		t.Fatalf("message %q carries the user name", ws.Message)
	}
	refusedAs(t, partyAt("http://localhost:80@example.com/md"), "metadata", "http://example.com")
	refusedAs(t, receiverAt("http://alice:s3cret@"+origin+"/ssf"), "ssf", "http://"+origin)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the stub was reached %d time(s)", n)
	}
}

func TestWhitespaceAndControlCharactersAreRefused(t *testing.T) {
	server, hits := plainStub(t)
	for _, raw := range []string{server.URL + " @example.com/md", server.URL + "/m\td", server.URL + "\x00@example.com/md", "https://example.com/m\nd"} {
		var ws *wsfed.WsFedError
		if err := partyAt(raw); !errors.As(err, &ws) || ws.Code != "metadata" || !strings.Contains(ws.Message, "whitespace or a control character") {
			t.Fatalf("%q: %v", raw, err)
		}
	}
	var ws *wsfed.WsFedError
	if err := receiverAt(server.URL + "/s sf"); !errors.As(err, &ws) || ws.Code != "ssf" {
		t.Fatalf("transmitter with a space: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the stub was reached %d time(s)", n)
	}
}

func TestARedirectIsNotFollowed(t *testing.T) {
	// Redirects are never followed, so a 302 to plain http off loopback is
	// the answer and example.com is never dialled.
	server, _ := plainStub(t)
	var ws *wsfed.WsFedError
	if err := partyAt(server.URL + "/away"); !errors.As(err, &ws) || ws.Code != "metadata" || !strings.Contains(ws.Message, "answered HTTP 302") {
		t.Fatalf("redirect: %v", err)
	}
}

func TestPlainHTTPToLoopbackStillWorks(t *testing.T) {
	server, hits := plainStub(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	for _, host := range []string{"127.0.0.1", "localhost"} {
		if err := partyAt("http://" + host + ":" + port + "/md"); err != nil {
			t.Fatalf("metadata on %s: %v", host, err)
		}
		before := hits.Load()
		err := receiverAt("http://" + host + ":" + port + "/ssf")
		var ws *wsfed.WsFedError
		if !errors.As(err, &ws) || ws.Code != "ssf" || strings.Contains(ws.Message, plainRefused) {
			t.Fatalf("transmitter on %s: %v", host, err)
		}
		if hits.Load() <= before {
			t.Fatalf("the transmitter on %s was not reached", host)
		}
	}
	// Other loopback forms are not refused (a closed port fails to connect).
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, closedPort, _ := net.SplitHostPort(closed.Addr().String())
	closed.Close()
	for _, origin := range []string{"http://127.200.0.9:" + closedPort, "http://[::1]:" + closedPort, "http://LOCALHOST:" + closedPort} {
		if err := partyAt(origin + "/md"); err == nil || strings.Contains(err.Error(), plainRefused) {
			t.Fatalf("%s: %v", origin, err)
		}
	}
	refusedAs(t, partyAt("http://127.0.0.1.example.com/md"), "metadata", "http://127.0.0.1.example.com")
}

func TestHTTPSToAnUnreachableHostIsAConnectionError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	listener.Close()
	https := "https://127.0.0.1:" + port
	for _, err := range []error{partyAt(https + "/md"), receiverAt(https)} {
		if err == nil || strings.Contains(err.Error(), plainRefused) || !strings.HasPrefix(err.Error(), https) {
			t.Fatalf("https to a closed port: %v", err)
		}
	}
}
