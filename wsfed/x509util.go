// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

// KeyPair is a self-signed RSA certificate used as a public-key container.
type KeyPair struct {
	PrivateKeyPEM  string
	CertificatePEM string
	Certificate    *x509.Certificate
	PrivateKey     *rsa.PrivateKey
}

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var raw []byte
	value := n
	for value > 0 {
		raw = append([]byte{byte(value & 0xFF)}, raw...)
		value >>= 8
	}
	return append([]byte{byte(0x80 | len(raw))}, raw...)
}

func tlv(tag byte, content ...[]byte) []byte {
	body := []byte{}
	for _, part := range content {
		body = append(body, part...)
	}
	out := []byte{tag}
	out = append(out, derLen(len(body))...)
	out = append(out, body...)
	return out
}

func seq(content ...[]byte) []byte { return tlv(0x30, content...) }

func set(content ...[]byte) []byte { return tlv(0x31, content...) }

func oid(dotted string) []byte {
	parts := strings.Split(dotted, ".")
	nums := make([]int, len(parts))
	for i, part := range parts {
		n := 0
		for _, c := range part {
			n = n*10 + int(c-'0')
		}
		nums[i] = n
	}
	out := []byte{byte(nums[0]*40 + nums[1])}
	for _, number := range nums[2:] {
		var chunk []byte
		chunk = append(chunk, byte(number&0x7F))
		value := number >> 7
		for value > 0 {
			chunk = append([]byte{byte((value & 0x7F) | 0x80)}, chunk...)
			value >>= 7
		}
		out = append(out, chunk...)
	}
	return tlv(0x06, out)
}

func derTime(moment time.Time) []byte {
	moment = moment.UTC()
	iso := moment.Format("20060102150405") + "Z"
	if moment.Year() < 2050 {
		return tlv(0x17, []byte(iso[2:]))
	}
	return tlv(0x18, []byte(iso))
}

func derHeader(spki []byte, at int) (int, int) {
	first := spki[at+1]
	if first < 0x80 {
		start := at + 2
		return start, start + int(first)
	}
	count := int(first & 0x7F)
	length := 0
	for i := 0; i < count; i++ {
		length = length*256 + int(spki[at+2+i])
	}
	start := at + 2 + count
	return start, start + length
}

func subjectPublicKeyBits(spki []byte) []byte {
	body, _ := derHeader(spki, 0)
	_, algEnd := derHeader(spki, body)
	bitsBody, bitsEnd := derHeader(spki, algEnd)
	return spki[bitsBody+1 : bitsEnd]
}

func derName(commonName string) []byte {
	return seq(set(seq(oid("2.5.4.3"), tlv(0x0C, []byte(commonName)))))
}

// CreateSelfSignedKeyPair builds an RSA key and a certificate: digitalSignature and keyEncipherment, not a CA.
// The subject key identifier is the SHA-1 of the PKCS#1 RSAPublicKey.
func CreateSelfSignedKeyPair(commonName string, days, bits int) (*KeyPair, error) {
	if days <= 0 {
		days = 1095
	}
	if bits == 0 {
		bits = 3072
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		return nil, err
	}
	serial[0] &= 0x7F
	if serial[0] == 0 {
		serial[0] = 1
	}
	notBefore := time.Now().UTC().Add(-60 * time.Second).Truncate(time.Second)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(subjectPublicKeyBits(spki))
	keyID := sum[:]
	extensions := tlv(0xA3, seq(
		seq(oid("2.5.29.14"), tlv(0x04, tlv(0x04, keyID))),
		seq(oid("2.5.29.35"), tlv(0x04, seq(tlv(0x80, keyID)))),
		seq(oid("2.5.29.19"), tlv(0x01, []byte{0xFF}), tlv(0x04, seq())),
		seq(oid("2.5.29.15"), tlv(0x01, []byte{0xFF}), tlv(0x04, tlv(0x03, []byte{0x05, 0xA0}))),
	))
	sha256RSA := seq(oid("1.2.840.113549.1.1.11"), []byte{0x05, 0x00})
	tbs := seq(
		tlv(0xA0, tlv(0x02, []byte{0x02})),
		tlv(0x02, serial),
		sha256RSA,
		derName(commonName),
		seq(derTime(notBefore), derTime(notAfter)),
		derName(commonName),
		spki,
		extensions,
	)
	hashed := sha256.Sum256(tbs)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	der := seq(tbs, sha256RSA, tlv(0x03, append([]byte{0}, signature...)))
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return &KeyPair{
		PrivateKeyPEM:  string(keyPEM),
		CertificatePEM: string(block),
		Certificate:    certificate,
		PrivateKey:     privateKey,
	}, nil
}
