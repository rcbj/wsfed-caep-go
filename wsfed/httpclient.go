// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"time"
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

func send(url string, method string, headers map[string]string, body *string, tlsIn *tlsMaterial, code string) (httpResult, error) {
	if method == "" {
		method = http.MethodGet
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return httpResult{}, fail(code, url+" is not an http(s) URL")
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
