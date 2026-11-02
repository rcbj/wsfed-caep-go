// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
	"unicode"
)

const (
	maxBytes = 2 * 1024 * 1024
	timeout  = 15 * time.Second
)

type httpResult struct {
	Status      int
	ContentType string
	Body        string
}

type tlsMaterial struct {
	CA   string
	Cert string
	Key  string
}

// isLoopbackHost is true for 127.0.0.0/8, ::1 and the name localhost: the
// hosts where plain http never leaves the machine. Nothing here resolves a
// name.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if strings.Contains(host, ":") {
		return ip.Equal(net.IPv6loopback)
	}
	return ip.To4() != nil && ip.To4()[0] == 127
}

// refuseUnsafeCharacters refuses a URL holding whitespace or a control
// character before it is parsed, rather than risk two parsers disagreeing on
// its host. The URL itself is not repeated: it may carry a secret.
func refuseUnsafeCharacters(rawURL, code string) error {
	for _, r := range rawURL {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fail(code, "the URL is refused: it contains whitespace or a control character")
		}
	}
	return nil
}

// refusePlainHTTP is nil unless rawURL is a plain http URL off loopback.
// Userinfo is never loopback, so "http://localhost:80@host/" cannot pass as
// localhost. The URL is parsed as net/http will dial it. The message names
// the scheme and host[:port] only: never userinfo, path, query or a secret.
func refusePlainHTTP(rawURL, code string) error {
	if len(rawURL) < 7 || !strings.EqualFold(rawURL[:7], "http://") {
		return nil
	}
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return fail(code, "a plain http URL that cannot be parsed is refused; use https")
	}
	if parsed.User == nil && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return fail(code, "http://"+parsed.Host+" is refused: plain http is allowed only to a loopback host (127.0.0.0/8, ::1, localhost); use https")
}

// send is the one function every fetch this package makes goes through: the
// identity provider's federation metadata (its signing keys) and the Shared
// Signals transmitter (configuration, JWKS, stream and poll: the SETs and the
// bearer token). None of them may travel in the clear off this machine, so
// plain http is refused before any DNS lookup or connection unless the host
// is loopback. Redirects are not followed (http.ErrUseLastResponse), so the
// URL checked here is the only one ever dialled.
func send(url string, method string, headers map[string]string, body *string, tlsIn *tlsMaterial, code string) (httpResult, error) {
	if method == "" {
		method = http.MethodGet
	}
	if err := refuseUnsafeCharacters(url, code); err != nil {
		return httpResult{}, err
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return httpResult{}, fail(code, url+" is not an http(s) URL")
	}
	if err := refusePlainHTTP(url, code); err != nil {
		return httpResult{}, err
	}
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(*body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return httpResult{}, failCause(code, url+": "+err.Error(), err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	transport := &http.Transport{}
	if strings.HasPrefix(url, "https://") {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsIn != nil && tlsIn.CA != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(tlsIn.CA)) {
				return httpResult{}, fail(code, url+": the CA certificate cannot be read")
			}
			cfg.RootCAs = pool
		}
		if tlsIn != nil && tlsIn.Cert != "" && tlsIn.Key != "" {
			pair, err := tls.X509KeyPair([]byte(tlsIn.Cert), []byte(tlsIn.Key))
			if err != nil {
				return httpResult{}, failCause(code, url+": "+err.Error(), err)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		transport.TLSClientConfig = cfg
	}
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "timeout") || strings.Contains(err.Error(), "deadline") {
			return httpResult{}, failCause(code, url+" did not answer within 15 s", err)
		}
		return httpResult{}, failCause(code, url+": "+err.Error(), err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return httpResult{}, failCause(code, url+": "+err.Error(), err)
	}
	if len(raw) > maxBytes {
		return httpResult{}, fail(code, url+" answered more than "+itoa(maxBytes)+" bytes")
	}
	return httpResult{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: string(raw)}, nil
}
