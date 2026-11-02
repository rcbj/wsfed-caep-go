// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Resolved is the configuration the relying party runs with.
// SignalsSet is false when signals is omitted or true, so the key is left off the result.
type Resolved struct {
	Realm                   string
	ReplyURL                string
	IdPMetadata             string
	ClockSkewMs             int
	WantAssertionsEncrypted bool
	AllowUnsolicited        bool
	RequestTokenType        bool
	SignalsSet              bool
	Signals                 bool
	PrivateKey              *rsa.PrivateKey
	Certificate             *x509.Certificate
	IdPCA                   string
	IdPEntityID             string
}

func (r *Resolved) sameCore(o *Resolved) bool {
	if r == nil || o == nil {
		return r == o
	}
	return r.Realm == o.Realm && r.ReplyURL == o.ReplyURL && r.IdPMetadata == o.IdPMetadata &&
		r.ClockSkewMs == o.ClockSkewMs && r.WantAssertionsEncrypted == o.WantAssertionsEncrypted &&
		r.AllowUnsolicited == o.AllowUnsolicited && r.RequestTokenType == o.RequestTokenType &&
		r.IdPCA == o.IdPCA && r.IdPEntityID == o.IdPEntityID &&
		sameKey(r.PrivateKey, o.PrivateKey) && sameCert(r.Certificate, o.Certificate)
}

func sameKey(a, b *rsa.PrivateKey) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.N.Cmp(b.N) == 0 && a.E == b.E && a.D.Cmp(b.D) == 0
}

func sameCert(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

func isPEM(value string) bool { return strings.Contains(value, "-----BEGIN ") }

func material(value, baseDir, what string) (string, error) {
	if strings.HasPrefix(value, "env:") {
		name := value[4:]
		got, ok := os.LookupEnv(name)
		if !ok || got == "" {
			return "", fail("config", what+" environment variable "+name+" is not set")
		}
		value = got
	}
	if strings.HasPrefix(value, "file:") {
		value = value[5:]
	}
	if isPEM(value) {
		return value, nil
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, value)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", failCause("config", what+" is neither a PEM nor a readable file ("+path+")", err)
	}
	return string(raw), nil
}

func absoluteURL(value any, what string) (string, error) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", fail("config", what+" is required")
	}
	if !(strings.HasPrefix(text, "https://") || strings.HasPrefix(text, "http://")) {
		return "", fail("config", what+" must be an absolute http(s) URL, not "+text)
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(text, "https://"), "http://")
	if rest == "" || strings.HasPrefix(rest, "/") {
		return "", fail("config", what+" must be an absolute http(s) URL, not "+text)
	}
	return text, nil
}

func flag(value any, present bool, fallback bool, what string) (bool, error) {
	if !present || value == nil {
		return fallback, nil
	}
	b, ok := value.(bool)
	if !ok {
		return false, fail("config", what+" must be true or false")
	}
	return b, nil
}

func asFloat(value any) (float64, bool) {
	switch n := value.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		if math.IsNaN(n) {
			return 0, false
		}
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	default:
		return 0, false
	}
}

func whole(value any) bool {
	switch n := value.(type) {
	case int, int32, int64:
		return true
	case json.Number:
		return !strings.ContainsAny(n.String(), ".eE")
	case float64:
		return n == math.Trunc(n)
	default:
		return false
	}
}

func idpMetadataRef(value, baseDir string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "env:") {
		name := value[4:]
		got, ok := os.LookupEnv(name)
		if !ok || got == "" {
			return "", fail("config", "idpMetadata environment variable "+name+" is not set")
		}
		value = strings.TrimSpace(got)
	}
	if strings.HasPrefix(value, "file:") {
		value = value[5:]
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "<") {
		return value, nil
	}
	if filepath.IsAbs(value) {
		return value, nil
	}
	return filepath.Join(baseDir, value), nil
}

func loadPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fail("config", "the private key or certificate cannot be read: not a PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fail("config", "the private key is not RSA; an RSA key is required")
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, failCause("config", "the private key or certificate cannot be read: "+err.Error(), err)
	}
	return key, nil
}

func loadCert(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fail("config", "the private key or certificate cannot be read: not a PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, failCause("config", "the private key or certificate cannot be read: "+err.Error(), err)
	}
	return cert, nil
}

// ResolveConfig reads a configuration object. signals omitted or true is left off the result.
func ResolveConfig(config map[string]any, baseDir string) (*Resolved, error) {
	if config == nil {
		return nil, fail("config", "the configuration must be an object")
	}
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}
	realm, _ := config["realm"].(string)
	if strings.TrimSpace(realm) == "" {
		return nil, fail("config", "realm is required")
	}
	reply, err := absoluteURL(config["replyUrl"], "replyUrl")
	if err != nil {
		return nil, err
	}
	rawMeta, ok := config["idpMetadata"].(string)
	if !ok || strings.TrimSpace(rawMeta) == "" {
		return nil, fail("config", "idpMetadata is required")
	}
	meta, err := idpMetadataRef(rawMeta, baseDir)
	if err != nil {
		return nil, err
	}
	skew := 60.0
	if value, present := config["clockSkewSeconds"]; present && value != nil {
		parsed, ok := asFloat(value)
		if !ok || parsed < 0 || parsed > 600 {
			return nil, fail("config", "clockSkewSeconds must be a number from 0 to 600")
		}
		skew = parsed
	}
	skewMs := int(skew) * 1000
	if !whole(config["clockSkewSeconds"]) && config["clockSkewSeconds"] != nil {
		skewMs = int(skew * 1000)
	}
	if _, present := config["clockSkewSeconds"]; !present || config["clockSkewSeconds"] == nil {
		skewMs = 60 * 1000
	}
	signals, err := flag(config["signals"], hasKey(config, "signals"), true, "signals")
	if err != nil {
		return nil, err
	}
	want, err := flag(config["wantAssertionsEncrypted"], hasKey(config, "wantAssertionsEncrypted"), false, "wantAssertionsEncrypted")
	if err != nil {
		return nil, err
	}
	allow, err := flag(config["allowUnsolicited"], hasKey(config, "allowUnsolicited"), false, "allowUnsolicited")
	if err != nil {
		return nil, err
	}
	requestType, err := flag(config["requestTokenType"], hasKey(config, "requestTokenType"), true, "requestTokenType")
	if err != nil {
		return nil, err
	}
	out := &Resolved{
		Realm: realm, ReplyURL: reply, IdPMetadata: meta, ClockSkewMs: skewMs,
		WantAssertionsEncrypted: want, AllowUnsolicited: allow, RequestTokenType: requestType,
	}
	if !signals {
		out.SignalsSet = true
		out.Signals = false
	}
	_, hasKeyMat := config["privateKey"]
	_, hasCert := config["certificate"]
	keyPresent := hasKeyMat && config["privateKey"] != nil
	certPresent := hasCert && config["certificate"] != nil
	if keyPresent != certPresent {
		return nil, fail("config", "privateKey and certificate go together: give both or neither")
	}
	if keyPresent && certPresent {
		keyText, ok := config["privateKey"].(string)
		certText, ok2 := config["certificate"].(string)
		if !ok || !ok2 {
			return nil, fail("config", "the private key or certificate cannot be read: not a string")
		}
		keyPEM, err := material(keyText, baseDir, "privateKey")
		if err != nil {
			return nil, err
		}
		certPEM, err := material(certText, baseDir, "certificate")
		if err != nil {
			return nil, err
		}
		privateKey, err := loadPrivateKey(keyPEM)
		if err != nil {
			return nil, err
		}
		certificate, err := loadCert(certPEM)
		if err != nil {
			return nil, err
		}
		pub, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok || pub.N.Cmp(privateKey.N) != 0 || pub.E != privateKey.E {
			return nil, fail("config", "the certificate is not for the private key")
		}
		out.PrivateKey = privateKey
		out.Certificate = certificate
	} else if out.WantAssertionsEncrypted {
		return nil, fail("config", "wantAssertionsEncrypted needs privateKey and certificate: the assertion is encrypted to them")
	}
	if ca, ok := config["idpCa"].(string); ok && ca != "" {
		text, err := material(ca, baseDir, "idpCa")
		if err != nil {
			return nil, err
		}
		out.IdPCA = text
	}
	if id, ok := config["idpEntityId"].(string); ok && id != "" {
		out.IdPEntityID = id
	}
	return out, nil
}

func hasKey(config map[string]any, key string) bool {
	_, ok := config[key]
	return ok
}

// ReadConfigFile loads JSON and applies overrides. A nil override value is ignored.
func ReadConfigFile(path string, overrides map[string]any) (*Resolved, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, failCause("config", path+" cannot be read as JSON: "+err.Error(), err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var parsed map[string]any
	if err := dec.Decode(&parsed); err != nil {
		return nil, failCause("config", path+" cannot be read as JSON: "+err.Error(), err)
	}
	for key, value := range overrides {
		if value != nil {
			parsed[key] = value
		}
	}
	return ResolveConfig(parsed, filepath.Dir(absPath(path)))
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
