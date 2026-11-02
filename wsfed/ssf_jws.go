// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"math/big"
	"regexp"
	"strings"
)

type jwsAlg struct {
	hash  crypto.Hash
	kty   string
	pss   bool
	p1363 bool
	name  string
}

var jwsAlgs = map[string]jwsAlg{
	"RS256":   {crypto.SHA256, "RSA", false, false, "sha256"},
	"RS384":   {crypto.SHA384, "RSA", false, false, "sha384"},
	"RS512":   {crypto.SHA512, "RSA", false, false, "sha512"},
	"PS256":   {crypto.SHA256, "RSA", true, false, "sha256"},
	"PS384":   {crypto.SHA384, "RSA", true, false, "sha384"},
	"PS512":   {crypto.SHA512, "RSA", true, false, "sha512"},
	"ES256":   {crypto.SHA256, "EC", false, true, "sha256"},
	"ES384":   {crypto.SHA384, "EC", false, true, "sha384"},
	"ES512":   {crypto.SHA512, "EC", false, true, "sha512"},
	"EdDSA":   {0, "OKP", false, false, ""},
	"Ed25519": {0, "OKP", false, false, ""},
}

var supportedJWSAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"}

var b64urlRe = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

func b64url(value, what string) ([]byte, error) {
	if !b64urlRe.MatchString(value) {
		return nil, fail("signature", "the SET's "+what+" is not base64url")
	}
	out, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, failCause("signature", "the SET's "+what+" is not base64url", err)
	}
	return out, nil
}

func b64int(value string) (*big.Int, error) {
	raw, err := b64url(value, "key")
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func hashFor(id crypto.Hash) hash.Hash {
	switch id {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

func keyFor(jwk map[string]any) (any, error) {
	kty := stringOf(jwk["kty"])
	defer func() {}()
	switch kty {
	case "RSA":
		n, err := b64int(stringOf(jwk["n"]))
		if err != nil {
			return nil, err
		}
		e, err := b64int(stringOf(jwk["e"]))
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		x, err := b64int(stringOf(jwk["x"]))
		if err != nil {
			return nil, err
		}
		y, err := b64int(stringOf(jwk["y"]))
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch stringOf(jwk["crv"]) {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fail("signature", "the transmitter's key "+stringOf(jwk["kid"])+" cannot be read: unsupported curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		raw, err := b64url(stringOf(jwk["x"]), "key")
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fail("signature", "the transmitter's key "+stringOf(jwk["kid"])+" cannot be read: bad OKP length")
		}
		return ed25519.PublicKey(raw), nil
	default:
		return nil, fail("signature", "the transmitter's key "+stringOf(jwk["kid"])+" cannot be read: unsupported kty "+kty)
	}
}

// VerifyCompactJWS checks a Security Event Token. none and HMAC are refused.
func VerifyCompactJWS(token string, keys []map[string]any) (map[string]any, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fail("signature", "the SET is not a compact JWS")
	}
	headerRaw, err := b64url(parts[0], "header")
	if err != nil {
		return nil, nil, err
	}
	payloadRaw, err := b64url(parts[1], "payload")
	if err != nil {
		return nil, nil, err
	}
	var header, payload map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil || header == nil {
		return nil, nil, failCause("signature", "the SET's header or payload is not JSON", err)
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil || payload == nil {
		return nil, nil, failCause("signature", "the SET's header or payload is not JSON", err)
	}
	alg := stringOf(header["alg"])
	spec, ok := jwsAlgs[alg]
	if !ok {
		shown := alg
		if shown == "" {
			shown = "(no alg)"
		}
		return nil, nil, fail("signature", "the SET is signed with "+shown+", which this receiver does not verify ("+strings.Join(supportedJWSAlgs, ", ")+")")
	}
	if _, crit := header["crit"]; crit {
		return nil, nil, fail("signature", "the SET's header has a crit member this receiver does not understand")
	}
	kid := ""
	if text, ok := header["kid"].(string); ok {
		kid = text
	}
	var candidates []map[string]any
	for _, key := range keys {
		if kid != "" && stringOf(key["kid"]) != kid {
			continue
		}
		if stringOf(key["kty"]) != spec.kty {
			continue
		}
		if use := stringOf(key["use"]); use != "" && use != "sig" {
			continue
		}
		if keyAlg := stringOf(key["alg"]); keyAlg != "" && keyAlg != alg {
			continue
		}
		candidates = append(candidates, key)
	}
	if len(candidates) == 0 {
		suffix := ""
		if kid != "" {
			suffix = " with kid " + kid
		}
		return nil, nil, fail("signature", "the transmitter publishes no "+spec.kty+" signing key"+suffix)
	}
	data := []byte(parts[0] + "." + parts[1])
	signature, err := b64url(parts[2], "signature")
	if err != nil {
		return nil, nil, err
	}
	for _, jwk := range candidates {
		key, err := keyFor(jwk)
		if err != nil {
			continue
		}
		if verifyJWS(key, spec, data, signature) {
			return header, payload, nil
		}
	}
	return nil, nil, fail("signature", "the SET's signature does not verify against the transmitter's keys")
}

func verifyJWS(key any, spec jwsAlg, data, signature []byte) bool {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		sum := hashFor(spec.hash).Sum(nil)
		hashed := sum
		_ = hashed
		h := hashFor(spec.hash)
		h.Write(data)
		digest := h.Sum(nil)
		if spec.pss {
			return rsa.VerifyPSS(pub, spec.hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}) == nil
		}
		return rsa.VerifyPKCS1v15(pub, spec.hash, digest, signature) == nil
	case *ecdsa.PublicKey:
		if len(signature)%2 != 0 {
			return false
		}
		half := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:half])
		s := new(big.Int).SetBytes(signature[half:])
		h := hashFor(spec.hash)
		h.Write(data)
		return ecdsa.Verify(pub, h.Sum(nil), r, s)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, data, signature)
	default:
		return false
	}
}
