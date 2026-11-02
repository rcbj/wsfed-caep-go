// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/rcbj/wsfed-caep-go/wsfed"
	"os"
	"path/filepath"
	"testing"
)

var skiOID = []byte{0x06, 0x03, 0x55, 0x1d, 0x0e}
var akiOID = []byte{0x06, 0x03, 0x55, 0x1d, 0x23}

func keyIDAfter(cert, oid []byte) []byte {
	at := bytes.Index(cert, oid)
	if at < 0 {
		return nil
	}
	rest := cert[at+len(oid):]
	marker := bytes.IndexByte(rest, 0x14)
	start := at + len(oid) + marker + 1
	return cert[start : start+20]
}

func TestSignsItselfAndNamesItsKey(t *testing.T) {
	pair, err := wsfed.CreateSelfSignedKeyPair("rp", 30, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.Certificate.CheckSignature(pair.Certificate.SignatureAlgorithm, pair.Certificate.RawTBSCertificate, pair.Certificate.Signature); err != nil {
		t.Fatal(err)
	}
	spki := x509.MarshalPKCS1PublicKey(&pair.PrivateKey.PublicKey)
	want := sha1.Sum(spki)
	der := pair.Certificate.Raw
	if !bytes.Equal(keyIDAfter(der, skiOID), want[:]) || !bytes.Equal(keyIDAfter(der, akiOID), want[:]) {
		t.Fatalf("ski %x aki %x want %x", keyIDAfter(der, skiOID), keyIDAfter(der, akiOID), want[:])
	}
}

func TestTwoCertificatesOfOneNameHaveDifferentKeyIdentifiers(t *testing.T) {
	one, err := wsfed.CreateSelfSignedKeyPair("localhost:3000", 30, 2048)
	if err != nil {
		t.Fatal(err)
	}
	two, err := wsfed.CreateSelfSignedKeyPair("localhost:3000", 30, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if one.Certificate.Subject.String() != two.Certificate.Subject.String() {
		t.Fatal(one.Certificate.Subject, two.Certificate.Subject)
	}
	if bytes.Equal(keyIDAfter(one.Certificate.Raw, skiOID), keyIDAfter(two.Certificate.Raw, skiOID)) {
		t.Fatal("same key id")
	}
}

func TestGenerateKeysNamesTheCertificateAfterTheRealm(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "wsfed.json")
	raw, _ := json.Marshal(map[string]any{
		"realm": "http://localhost:3000/", "replyUrl": "http://localhost:3000/wsfed",
		"idpMetadata": "x", "privateKey": "k.pem", "certificate": "c.pem",
	})
	if err := os.WriteFile(config, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := wsfed.Main([]string{"generate-keys", "--config", config, "--bits", "2048"}, bytes.NewBuffer(nil)); code != 0 {
		t.Fatal(code)
	}
	pemBytes, err := os.ReadFile(filepath.Join(dir, "c.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want := "CN=wsfed-caep-nodejs relying party http://localhost:3000/"
	if cert.Subject.String() != want && cert.Subject.CommonName != "wsfed-caep-nodejs relying party http://localhost:3000/" {
		t.Fatal(cert.Subject.String())
	}
	if cert.Subject.String() != want {
		t.Fatal(cert.Subject.String())
	}
}
