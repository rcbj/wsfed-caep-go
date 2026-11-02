// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strings"

	"github.com/beevik/etree"
)

type cipherSpec struct {
	name      string
	gcm       bool
	keyLength int
}

var ciphers = map[string]cipherSpec{
	"http://www.w3.org/2009/xmlenc11#aes128-gcm":  {"aes-128-gcm", true, 16},
	"http://www.w3.org/2009/xmlenc11#aes192-gcm":  {"aes-192-gcm", true, 24},
	"http://www.w3.org/2009/xmlenc11#aes256-gcm":  {"aes-256-gcm", true, 32},
	"http://www.w3.org/2001/04/xmlenc#aes128-cbc": {"aes-128-cbc", false, 16},
	"http://www.w3.org/2001/04/xmlenc#aes192-cbc": {"aes-192-cbc", false, 24},
	"http://www.w3.org/2001/04/xmlenc#aes256-cbc": {"aes-256-cbc", false, 32},
}

const (
	oaepMgf1p = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	oaep11    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

var oaepDigests = map[string]string{
	"http://www.w3.org/2000/09/xmldsig#sha1":        "sha1",
	"http://www.w3.org/2001/04/xmlenc#sha256":       "sha256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
	"http://www.w3.org/2001/04/xmlenc#sha512":       "sha512",
}

var mgfs = map[string]string{
	"http://www.w3.org/2009/xmlenc11#mgf1sha1":   "sha1",
	"http://www.w3.org/2009/xmlenc11#mgf1sha256": "sha256",
	"http://www.w3.org/2009/xmlenc11#mgf1sha384": "sha384",
	"http://www.w3.org/2009/xmlenc11#mgf1sha512": "sha512",
}

func decFail(message string) error { return fail("decryption", message) }

func decCause(message string, cause error) error {
	return failCause("decryption", message, cause)
}

func b64Text(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
}

func hashNew(name string) hash.Hash {
	switch name {
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	default:
		return sha1.New()
	}
}

func unwrapKey(encryptedKey *etree.Element, key *rsa.PrivateKey) ([]byte, error) {
	method, err := child(encryptedKey, NSXenc, "EncryptionMethod")
	if err != nil {
		return nil, err
	}
	alg := ""
	if method != nil {
		alg, _ = attr(method, "Algorithm")
	}
	if alg != oaepMgf1p && alg != oaep11 {
		shown := alg
		if shown == "" {
			shown = "(none)"
		}
		return nil, decFail("the content key is wrapped with " + shown + "; only RSA-OAEP is accepted")
	}
	var digestMethod *etree.Element
	if method != nil {
		digestMethod, err = child(method, NSDS, "DigestMethod")
		if err != nil {
			return nil, err
		}
	}
	digestName := "sha1"
	if digestMethod != nil {
		digestAlg, _ := attr(digestMethod, "Algorithm")
		if digestAlg != "" {
			name, ok := oaepDigests[digestAlg]
			if !ok {
				return nil, decFail("the OAEP digest " + digestAlg + " is not supported")
			}
			digestName = name
		}
	}
	mgf := "sha1"
	if alg == oaep11 && method != nil {
		mgfEl, err := child(method, NSXenc11, "MGF")
		if err != nil {
			return nil, err
		}
		if mgfEl != nil {
			mgfAlg, _ := attr(mgfEl, "Algorithm")
			if mgfAlg != "" {
				name, ok := mgfs[mgfAlg]
				if !ok {
					return nil, decFail("the OAEP mask generation function " + mgfAlg + " is not supported")
				}
				mgf = name
			}
		}
	}
	if mgf != digestName {
		return nil, decFail("OAEP with digest " + digestName + " and MGF1 " + mgf + " is not supported; node:crypto uses one hash for both")
	}
	values := descendants(encryptedKey, NSXenc, "CipherValue")
	raw := ""
	if len(values) > 0 {
		raw = textOf(values[0])
	}
	blob, err := b64Text(raw)
	if err != nil {
		return nil, decCause("the content key could not be unwrapped with this relying party's key", err)
	}
	plain, err := rsa.DecryptOAEP(hashNew(digestName), rand.Reader, key, blob, nil)
	if err != nil {
		return nil, decCause("the content key could not be unwrapped with this relying party's key", err)
	}
	return plain, nil
}

func decryptElement(encrypted *etree.Element, key *rsa.PrivateKey) (string, error) {
	data := encrypted
	if !isEl(encrypted, NSXenc, "EncryptedData") {
		var err error
		data, err = child(encrypted, NSXenc, "EncryptedData")
		if err != nil {
			return "", err
		}
	}
	if data == nil {
		return "", decFail("<" + encrypted.Tag + "> has no EncryptedData")
	}
	method, err := child(data, NSXenc, "EncryptionMethod")
	if err != nil {
		return "", err
	}
	alg := ""
	if method != nil {
		alg, _ = attr(method, "Algorithm")
	}
	spec, ok := ciphers[alg]
	if !ok {
		shown := alg
		if shown == "" {
			shown = "(none)"
		}
		return "", decFail("the content is encrypted with " + shown + ", which is not supported")
	}
	keys := descendants(encrypted, NSXenc, "EncryptedKey")
	if len(keys) == 0 {
		return "", decFail("<" + encrypted.Tag + "> carries no EncryptedKey")
	}
	contentKey, err := unwrapKey(keys[0], key)
	if err != nil {
		return "", err
	}
	if len(contentKey) != spec.keyLength {
		return "", decFail("the content key is " + itoa(len(contentKey)) + " bytes; " + spec.name + " needs " + itoa(spec.keyLength))
	}
	cipherData, err := child(data, NSXenc, "CipherData")
	if err != nil {
		return "", err
	}
	var valueEl *etree.Element
	if cipherData != nil {
		valueEl, err = child(cipherData, NSXenc, "CipherValue")
		if err != nil {
			return "", err
		}
	}
	rawText := ""
	if valueEl != nil {
		rawText = textOf(valueEl)
	}
	raw, err := b64Text(rawText)
	if err != nil {
		return "", decCause("the content could not be decrypted", err)
	}
	if spec.gcm {
		if len(raw) < 12+16 {
			return "", decFail("the ciphertext is too short")
		}
		block, err := aes.NewCipher(contentKey)
		if err != nil {
			return "", decCause("the content could not be decrypted", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", decCause("the content could not be decrypted", err)
		}
		plain, err := gcm.Open(nil, raw[:12], raw[12:], nil)
		if err != nil {
			return "", decCause("the content could not be decrypted", err)
		}
		return string(plain), nil
	}
	if len(raw) < 32 || len(raw)%16 != 0 {
		return "", decFail("the ciphertext is not a whole number of blocks")
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return "", decCause("the content could not be decrypted", err)
	}
	iv, ct := raw[:16], raw[16:]
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > 16 {
		return "", decFail("the decrypted content is not padded as XML Encryption pads it")
	}
	return string(plain[:len(plain)-pad]), nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
