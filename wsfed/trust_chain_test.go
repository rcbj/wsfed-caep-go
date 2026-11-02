// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

// idpCa: the install script writes the whole listener CA trust chain to the
// file the parameter names, and the library takes that file as its trust
// store, verifying the host name and refusing a forged leaf in front of the
// real CAs.
//
// The stub provider is HTTPS on a four-certificate chain shaped like iya-sts's
// (leaf, TLS Issuing CA, Intermediate, Root) and publishes it, leaf first, at
// GET /tls/server-certificate. The scripts run with the test image's python3
// and openssl (Dockerfile, test stage).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const defaultIdpCa = "generated/idp-ca.pem"

type chainCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func makeChainCert(t *testing.T, cn string, issuer *chainCert, ca bool, ip string) *chainCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &chainCert{cert: cert, key: key, pem: string(block)}
}

const stubMetadataPath = "/wsfed/metadata/demo"

// startChainProvider serves the leaf, then presented (the CAs the handshake sends).
func startChainProvider(t *testing.T, leaf *chainCert, presented []*chainCert, published string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/tls/server-certificate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte(published))
	})
	mux.HandleFunc(stubMetadataPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte("<md:EntityDescriptor/>"))
	})
	chain := [][]byte{leaf.cert.Raw}
	for _, ca := range presented {
		chain = append(chain, ca.cert.Raw)
	}
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.key}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

type stsChain struct {
	root, intermediate, issuing, leaf *chainCert
	published                         string
}

func newStsChain(t *testing.T) stsChain {
	t.Helper()
	root := makeChainCert(t, "sts Root CA", nil, true, "")
	intermediate := makeChainCert(t, "sts Intermediate CA", root, true, "")
	issuing := makeChainCert(t, "sts TLS Issuing CA", intermediate, true, "")
	leaf := makeChainCert(t, "127.0.0.1", issuing, false, "127.0.0.1")
	return stsChain{
		root: root, intermediate: intermediate, issuing: issuing, leaf: leaf,
		published: leaf.pem + issuing.pem + intermediate.pem + root.pem,
	}
}

func (c stsChain) start(t *testing.T) string {
	return startChainProvider(t, c.leaf, []*chainCert{c.issuing, c.intermediate}, c.published)
}

// chainDemoDir writes the shipped demo/wsfed.json into a temp dir with
// placeholder key files, so the install script does not try to generate a key
// pair.
func chainDemoDir(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "demo", "wsfed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rp.key", "rp.crt"} {
		if err := os.WriteFile(filepath.Join(dir, "generated", name), []byte("placeholder\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(dir, "wsfed.json"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runPython(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("python3 is not on PATH; run the suite with docker build --target test .")
	}
	abs := make([]string, 0, len(args))
	for i, arg := range args {
		if i == 0 {
			arg, _ = filepath.Abs(filepath.Join("..", arg))
		}
		abs = append(abs, arg)
	}
	cmd := exec.Command("python3", abs...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestShippedDemoNamesGeneratedIdpCaPem(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "demo", "wsfed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if config["idpCa"] != "file:"+defaultIdpCa {
		t.Fatalf("idpCa %v", config["idpCa"])
	}
}

func TestInstallScriptWritesWholeChainToIdpCa(t *testing.T) {
	chain := newStsChain(t)
	origin := chain.start(t)
	dir := chainDemoDir(t)
	// A stale single certificate is replaced: every run writes the chain.
	if err := os.WriteFile(filepath.Join(dir, defaultIdpCa), []byte(chain.root.pem), 0o644); err != nil {
		t.Fatal(err)
	}
	// No admin secret: the install script saves the chain first, then stops
	// at the missing secret. The chain is what this test is about.
	out, err := runPython(t, []string{"ADMIN_API_CLIENT_SECRET=", "STS_ADMIN_API_CLIENT_SECRET=", "PUBLIC_URL=http://127.0.0.1:3000"},
		"scripts/configure_iya_sts.py", "--config", filepath.Join(dir, "wsfed.json"), "--idp", origin)
	if err == nil {
		t.Fatalf("the install script ran on without an admin secret:\n%s", out)
	}
	target := filepath.Join(dir, defaultIdpCa)
	saved, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("no chain at %s: %v\n%s", target, readErr, out)
	}
	if string(saved) != chain.published {
		t.Fatalf("saved chain is not the published one:\n%s\n%s", saved, out)
	}
	if strings.Count(string(saved), "BEGIN CERTIFICATE") != 4 {
		t.Fatalf("saved %d certificates", strings.Count(string(saved), "BEGIN CERTIFICATE"))
	}
	if !strings.Contains(out, "(4 certificate(s)) to "+target) || !strings.Contains(out, "CN=sts Root CA") {
		t.Fatalf("output does not name the path and the anchor:\n%s", out)
	}
	digest := sha256.Sum256(chain.root.cert.Raw)
	parts := make([]string, len(digest))
	for i, b := range digest {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	if !strings.Contains(out, "sha256 "+strings.Join(parts, ":")) {
		t.Fatalf("output does not carry the anchor's SHA-256:\n%s", out)
	}
}

func TestRefreshEntryPointWritesIdpCa(t *testing.T) {
	chain := newStsChain(t)
	origin := chain.start(t)
	dir := chainDemoDir(t)
	out, err := runPython(t, nil, "scripts/trust_chain.py", "--config", filepath.Join(dir, "wsfed.json"), "--idp", origin)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	saved, err := os.ReadFile(filepath.Join(dir, defaultIdpCa))
	if err != nil || string(saved) != chain.published {
		t.Fatalf("refresh did not write the chain: %v\n%s", err, out)
	}
}

func TestLibraryTrustsProviderThroughSavedFile(t *testing.T) {
	chain := newStsChain(t)
	origin := chain.start(t)
	dir := chainDemoDir(t)
	url := origin + stubMetadataPath
	if _, err := send(url, "GET", nil, nil, nil, "metadata"); err == nil {
		t.Fatal("the stub was trusted without idpCa")
	}
	if out, err := runPython(t, nil, "scripts/trust_chain.py", "--config", filepath.Join(dir, "wsfed.json"), "--idp", origin); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// The demo's own configuration, resolved the way the demo resolves it,
	// without the key pair (the placeholders are not keys).
	config := map[string]any{
		"realm": "http://127.0.0.1:3000/", "replyUrl": "http://127.0.0.1:3000/wsfed",
		"idpMetadata": url, "idpCa": "file:" + defaultIdpCa,
	}
	resolved, err := ResolveConfig(config, dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.IdPCA != chain.published {
		t.Fatal("idpCa resolved to something other than the saved chain")
	}
	answer, err := send(url, "GET", nil, nil, &tlsMaterial{CA: resolved.IdPCA}, "metadata")
	if err != nil {
		t.Fatal(err)
	}
	if answer.Status != 200 || answer.Body != "<md:EntityDescriptor/>" {
		t.Fatalf("metadata answered %d %s", answer.Status, answer.Body)
	}
	// RefreshMetadata goes the same way: the fetch succeeds and only the
	// stub's empty document is refused.
	party := &RelyingParty{Config: resolved}
	if _, err := party.RefreshMetadata(); err == nil || strings.Contains(err.Error(), "certificate") {
		t.Fatalf("RefreshMetadata through the saved chain: %v", err)
	}
	// The root alone is enough: every PEM block of the file is a trust anchor,
	// not only the first (which is the leaf).
	if _, err := send(url, "GET", nil, nil, &tlsMaterial{CA: chain.root.pem}, "metadata"); err != nil {
		t.Fatalf("root only: %v", err)
	}
	// So is the TLS Issuing CA: the presented leaf chains to it directly.
	if _, err := send(url, "GET", nil, nil, &tlsMaterial{CA: chain.issuing.pem}, "metadata"); err != nil {
		t.Fatalf("issuing CA only: %v", err)
	}
}

func TestLibraryVerifiesTheHostName(t *testing.T) {
	chain := newStsChain(t)
	origin := chain.start(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin, "https://"))
	ca := &tlsMaterial{CA: chain.published}
	if _, err := send("https://127.0.0.1:"+port+stubMetadataPath, "GET", nil, nil, ca, "metadata"); err != nil {
		t.Fatalf("127.0.0.1 through the IP SAN: %v", err)
	}
	// Right chain, wrong name: the leaf names only IP 127.0.0.1, not localhost.
	_, err := send("https://localhost:"+port+stubMetadataPath, "GET", nil, nil, ca, "metadata")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("localhost was accepted on a 127.0.0.1-only certificate: %v", err)
	}
}

func TestLibraryRefusesForgedLeafBeforeRealCAs(t *testing.T) {
	chain := newStsChain(t)
	forger := makeChainCert(t, "forger CA", nil, true, "")
	forged := makeChainCert(t, "127.0.0.1", forger, false, "127.0.0.1")
	// The forged leaf, followed by the real Issuing and Intermediate CAs.
	origin := startChainProvider(t, forged, []*chainCert{chain.issuing, chain.intermediate}, chain.published)
	if _, err := send(origin+stubMetadataPath, "GET", nil, nil, &tlsMaterial{CA: chain.published}, "metadata"); err == nil {
		t.Fatal("a forged leaf in front of the real CA certificates was trusted")
	}
}
