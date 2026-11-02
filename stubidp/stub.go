// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// Package stubidp signs SAML assertions with the same canonicalization the relying party verifies.
package stubidp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"time"

	"github.com/rcbj/wsfed-caep-go/wsfed"
)

const (
	IdPEntity = "https://idp.test"
	Passive   = "https://idp.test/wsfed"
	Realm     = "https://rp.test/"
	Reply     = "https://rp.test/wsfed"
	ds        = "http://www.w3.org/2000/09/xmldsig#"
	xenc      = "http://www.w3.org/2001/04/xmlenc#"
	xenc11    = "http://www.w3.org/2009/xmlenc11#"
	saml      = "urn:oasis:names:tc:SAML:2.0:assertion"
	claims    = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
)

var (
	RPKey   string
	RPCert  string
	IdPKey  string
	IdPCert string
	rpPub   *rsa.PublicKey
	idpPriv *rsa.PrivateKey
)

func init() {
	rp, err := wsfed.CreateSelfSignedKeyPair("rp", 30, 2048)
	if err != nil {
		panic(err)
	}
	idp, err := wsfed.CreateSelfSignedKeyPair("idp", 30, 2048)
	if err != nil {
		panic(err)
	}
	RPKey, RPCert = rp.PrivateKeyPEM, rp.CertificatePEM
	IdPKey, IdPCert = idp.PrivateKeyPEM, idp.CertificatePEM
	rpPub = &rp.PrivateKey.PublicKey
	idpPriv = idp.PrivateKey
}

func pemBody(value string) string {
	var b strings.Builder
	for _, line := range strings.Split(value, "\n") {
		if strings.Contains(line, "-----") || strings.TrimSpace(line) == "" {
			continue
		}
		b.WriteString(strings.TrimSpace(line))
	}
	return b.String()
}

type MetaOptions struct {
	KeyIn      string
	TokenTypes []string
	FedPrefix  string
	NoSTS      bool
}

func IdPMetadata(opts *MetaOptions) string {
	if opts == nil {
		opts = &MetaOptions{}
	}
	fed := opts.FedPrefix
	if fed == "" {
		fed = "fed"
	}
	key := `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + pemBody(IdPCert) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
	types := opts.TokenTypes
	if types == nil {
		types = []string{"urn:oasis:names:tc:SAML:1.0:assertion", "urn:oasis:names:tc:SAML:2.0:assertion"}
	}
	var typeXML strings.Builder
	for _, token := range types {
		typeXML.WriteString(`<` + fed + `:TokenType Uri="` + token + `"/>`)
	}
	keyIn := opts.KeyIn
	if keyIn == "" {
		keyIn = "sts"
	}
	stsKey := key
	if keyIn == "idpsso" {
		stsKey = ""
	}
	sts := ""
	if !opts.NoSTS {
		sts = `
  <md:RoleDescriptor xsi:type="` + fed + `:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    ` + stsKey + `
    <` + fed + `:TokenTypesOffered>` + typeXML.String() + `</` + fed + `:TokenTypesOffered>
    <` + fed + `:SecurityTokenServiceEndpoint><wsa:EndpointReference><wsa:Address>https://idp.test/sts</wsa:Address></wsa:EndpointReference></` + fed + `:SecurityTokenServiceEndpoint>
    <` + fed + `:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>` + Passive + `</wsa:Address></wsa:EndpointReference></` + fed + `:PassiveRequestorEndpoint>
  </md:RoleDescriptor>`
	}
	return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="` + ds + `" xmlns:` + fed + `="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" entityID="` + IdPEntity + `">` + sts + `
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ` + key + `
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/saml2/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`
}

func iso(offset time.Duration) string {
	moment := time.Now().UTC().Add(offset).Truncate(time.Millisecond)
	ms := moment.Nanosecond() / 1e6
	return moment.Format("2006-01-02T15:04:05.") + pad(ms) + "Z"
}

func pad(n int) string {
	s := ""
	if n == 0 {
		return "000"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

func newID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return "_" + base64.RawURLEncoding.EncodeToString(buf)
}

type AssertionOptions struct {
	Audience           *string
	Recipient          *string
	InResponseTo       string
	NotOnOrAfter       time.Duration
	NotOnOrAfterSet    bool
	Issuer             string
	NameID             string
	SessionIndex       string
	ExtraAttributes    string
	BareConfirmation   bool
	NoConditionsExpiry bool
}

type Made struct {
	XML string
	ID  string
}

func AssertionXML(opts *AssertionOptions) Made {
	if opts == nil {
		opts = &AssertionOptions{}
	}
	aid := newID()
	recipientAttr := ""
	recipient := Reply
	if opts.Recipient != nil {
		recipient = *opts.Recipient
	}
	if recipient != "" {
		recipientAttr = ` Recipient="` + recipient + `"`
	}
	irt := ""
	if opts.InResponseTo != "" {
		irt = ` InResponseTo="` + opts.InResponseTo + `"`
	}
	offset := 300 * time.Second
	if opts.NotOnOrAfterSet {
		offset = opts.NotOnOrAfter
	}
	confirmation := `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>`
	if !opts.BareConfirmation {
		confirmation = `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData` + recipientAttr + ` NotOnOrAfter="` + iso(offset) + `"` + irt + `/></saml:SubjectConfirmation>`
	}
	expiry := ` NotOnOrAfter="` + iso(offset) + `"`
	if opts.NoConditionsExpiry {
		expiry = ""
	}
	issuer := opts.Issuer
	if issuer == "" {
		issuer = IdPEntity
	}
	name := opts.NameID
	if name == "" {
		name = "alice-1234"
	}
	session := opts.SessionIndex
	if session == "" {
		session = "_session1"
	}
	audience := Realm
	if opts.Audience != nil {
		audience = *opts.Audience
	}
	xml := `<saml:Assertion xmlns:saml="` + saml + `" ID="` + aid + `" Version="2.0" IssueInstant="` + iso(0) + `">` +
		`<saml:Issuer>` + issuer + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` + name + `</saml:NameID>` +
		confirmation + `</saml:Subject>` +
		`<saml:Conditions NotBefore="` + iso(-5*time.Second) + `"` + expiry + `>` +
		`<saml:AudienceRestriction><saml:Audience>` + audience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`<saml:AttributeStatement><saml:Attribute Name="` + claims + `/nameidentifier"><saml:AttributeValue>urn:uuid:alice</saml:AttributeValue></saml:Attribute>` +
		`<saml:Attribute Name="` + claims + `/emailaddress" FriendlyName="mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>` +
		`<saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>` +
		opts.ExtraAttributes + `</saml:AttributeStatement>` +
		`<saml:AuthnStatement AuthnInstant="` + iso(-time.Second) + `" SessionIndex="` + session + `">` +
		`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
		`</saml:Assertion>`
	return Made{XML: xml, ID: aid}
}

func SignXML(xml, elementID, keyPEM, certPEM string) (string, error) {
	if keyPEM == "" {
		keyPEM = IdPKey
	}
	if certPEM == "" {
		certPEM = IdPCert
	}
	block, _ := pem.Decode([]byte(keyPEM))
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key = parsed.(*rsa.PrivateKey)
	} else {
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		key = parsed
	}
	_ = idpPriv
	_ = sha1.New
	_ = sha256.New
	return wsfed.SignEnveloped(xml, elementID, key, certPEM)
}

func SignedAssertion(opts *AssertionOptions) (Made, error) {
	made := AssertionXML(opts)
	xml, err := SignXML(made.XML, made.ID, "", "")
	if err != nil {
		return Made{}, err
	}
	return Made{XML: xml, ID: made.ID}, nil
}

func pkcs7(data []byte) []byte {
	pad := 16 - (len(data) % 16)
	out := append([]byte{}, data...)
	for i := 0; i < pad; i++ {
		out = append(out, byte(pad))
	}
	return out
}

func Encrypt(plain, cipherName, transport, wrapper string) (string, error) {
	if cipherName == "" {
		cipherName = "aes-256-gcm"
	}
	if transport == "" {
		transport = "mgf1p"
	}
	if wrapper == "" {
		wrapper = "EncryptedAssertion"
	}
	var key, value []byte
	var alg string
	switch cipherName {
	case "aes-256-gcm":
		key = make([]byte, 32)
		iv := make([]byte, 12)
		_, _ = rand.Read(key)
		_, _ = rand.Read(iv)
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		sealed := gcm.Seal(nil, iv, []byte(plain), nil)
		value = append(iv, sealed...)
		alg = xenc11 + "aes256-gcm"
	case "aes-128-cbc":
		key = make([]byte, 16)
		iv := make([]byte, 16)
		_, _ = rand.Read(key)
		_, _ = rand.Read(iv)
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		padded := pkcs7([]byte(plain))
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		value = append(iv, out...)
		alg = xenc + "aes128-cbc"
	default:
		return "", errString(cipherName)
	}
	var wrapped []byte
	var keyMethod string
	var err error
	switch transport {
	case "mgf1p":
		wrapped, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, rpPub, key, nil)
		keyMethod = `<xenc:EncryptionMethod Algorithm="` + xenc + `rsa-oaep-mgf1p"/>`
	case "oaep256":
		wrapped, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, rpPub, key, nil)
		keyMethod = `<xenc:EncryptionMethod Algorithm="` + xenc11 + `rsa-oaep"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF xmlns:xenc11="` + xenc11 + `" Algorithm="` + xenc11 + `mgf1sha256"/></xenc:EncryptionMethod>`
	default:
		return "", errString(transport)
	}
	if err != nil {
		return "", err
	}
	data := `<xenc:EncryptedData xmlns:xenc="` + xenc + `" Type="` + xenc + `Element">` +
		`<xenc:EncryptionMethod Algorithm="` + alg + `"/>` +
		`<ds:KeyInfo xmlns:ds="` + ds + `"><xenc:EncryptedKey>` + keyMethod +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(wrapped) + `</xenc:CipherValue></xenc:CipherData>` +
		`</xenc:EncryptedKey></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(value) + `</xenc:CipherValue></xenc:CipherData>` +
		`</xenc:EncryptedData>`
	if wrapper == "none" {
		return data, nil
	}
	return `<saml:` + wrapper + ` xmlns:saml="` + saml + `">` + data + `</saml:` + wrapper + `>`, nil
}

type errString string

func (e errString) Error() string { return string(e) }

type WResultOptions struct {
	Token      *string
	Trust      string
	AppliesTo  string
	TokenType  string
	Expires    time.Duration
	ExpiresSet bool
}

func WResult(opts *WResultOptions) (string, error) {
	if opts == nil {
		opts = &WResultOptions{}
	}
	body := ""
	if opts.Token != nil {
		body = *opts.Token
	} else {
		made, err := SignedAssertion(nil)
		if err != nil {
			return "", err
		}
		body = made.XML
	}
	ns := "http://schemas.xmlsoap.org/ws/2005/02/trust"
	if opts.Trust == "1.3" {
		ns = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	}
	wsu := "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	applies := Realm
	if opts.AppliesTo != "" {
		applies = opts.AppliesTo
	}
	expires := time.Hour
	if opts.ExpiresSet {
		expires = opts.Expires
	}
	tokenType := "urn:oasis:names:tc:SAML:2.0:assertion"
	if opts.TokenType != "" {
		tokenType = opts.TokenType
	}
	rstr := `<t:RequestSecurityTokenResponse xmlns:t="` + ns + `">` +
		`<t:Lifetime><wsu:Created xmlns:wsu="` + wsu + `">` + iso(0) + `</wsu:Created>` +
		`<wsu:Expires xmlns:wsu="` + wsu + `">` + iso(expires) + `</wsu:Expires></t:Lifetime>` +
		`<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">` +
		`<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">` +
		`<wsa:Address>` + applies + `</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>` +
		`<t:RequestedSecurityToken>` + body + `</t:RequestedSecurityToken>` +
		`<t:TokenType>` + tokenType + `</t:TokenType>` +
		`<t:RequestType>` + ns + `/Issue</t:RequestType><t:KeyType>` + ns + `/Bearer</t:KeyType>` +
		`</t:RequestSecurityTokenResponse>`
	if opts.Trust == "1.3" {
		return `<t:RequestSecurityTokenResponseCollection xmlns:t="` + ns + `">` + rstr + `</t:RequestSecurityTokenResponseCollection>`, nil
	}
	return rstr, nil
}

func Saml11() string {
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="` + newID() + `" Issuer="` + IdPEntity + `" IssueInstant="` + iso(0) + `"><saml:AttributeStatement><saml:Subject><saml:NameIdentifier>alice</saml:NameIdentifier></saml:Subject></saml:AttributeStatement></saml:Assertion>`
}
