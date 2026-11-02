// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto/rsa"
	"crypto/x509"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
)

var utcTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$`)

// Login is who signed in. Pointer fields are absent when the assertion did not carry them.
type Login struct {
	NameID                 string
	NameIDFormat           *string
	NameQualifier          *string
	SPNameQualifier        *string
	AuthnInstant           time.Time
	Attributes             map[string][]string
	AttributeFriendlyNames map[string]string
	Issuer                 string
	Realm                  string
	TrustVersion           string
	Encrypted              bool
	AssertionID            string
	NotOnOrAfter           time.Time
	SessionIndex           *string
	SessionNotOnOrAfter    *time.Time
	AuthnContextClassRef   *string
	RequestID              *string
	RelayState             *string
}

type tokenContext struct {
	Realm                   string
	ReplyURL                string
	IdPEntityID             string
	IdPCertificates         []*x509.Certificate
	DecryptionKey           *rsa.PrivateKey
	ClockSkewMs             int
	WantAssertionsEncrypted bool
	Replay                  *MemoryReplayCache
	Now                     time.Time
}

func invalid(message string) error { return fail("validation", message) }

func malformed(message string) error { return fail("message", message) }

func parseInstant(value, what string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	if !utcTime.MatchString(value) {
		return nil, invalid(what + " is not a UTC dateTime: " + value)
	}
	normalized := strings.Replace(value, "Z", "+00:00", 1)
	t, err := time.Parse(time.RFC3339Nano, normalized)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05Z07:00", normalized)
	}
	if err != nil {
		return nil, invalid(what + " is not a dateTime: " + value)
	}
	return &t, nil
}

func millis(t time.Time) int64 { return t.UnixMilli() }

func isoTime(moment time.Time) string {
	moment = moment.UTC()
	ms := moment.Nanosecond() / 1e6
	return moment.Format("2006-01-02T15:04:05.") + pad3(ms) + "Z"
}

func pad3(n int) string {
	if n < 0 {
		n = 0
	}
	s := itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

func nsOf(el *etree.Element) string {
	uri := elementNS(el)
	if uri == "" {
		return "no namespace"
	}
	return uri
}

func responseOf(root *etree.Element) (*etree.Element, string, string, error) {
	if isEl(root, NSTrust13, "RequestSecurityTokenResponseCollection") {
		all := children(root, NSTrust13, "RequestSecurityTokenResponse")
		if len(all) != 1 {
			return nil, "", "", malformed("the RequestSecurityTokenResponseCollection holds " + itoa(len(all)) + " responses; exactly one is accepted")
		}
		return all[0], NSTrust13, "1.3", nil
	}
	if isEl(root, NSTrust2005, "RequestSecurityTokenResponse") {
		return root, NSTrust2005, "2005/02", nil
	}
	if isEl(root, NSTrust13, "RequestSecurityTokenResponse") {
		return root, NSTrust13, "1.3", nil
	}
	return nil, "", "", malformed("wresult is a <" + root.Tag + "> in " + nsOf(root) + ", not a WS-Trust RequestSecurityTokenResponse")
}

func attrInstant(el *etree.Element, name, what string) (*time.Time, error) {
	if el == nil {
		return nil, nil
	}
	value, ok := attr(el, name)
	if !ok {
		return nil, nil
	}
	return parseInstant(value, what)
}

// ValidateToken reads a wresult and checks the SAML 2.0 assertion it carries.
func ValidateToken(wresult string, ctx tokenContext) (*Login, error) {
	now := ctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowMs := millis(now)
	skew := int64(ctx.ClockSkewMs)
	_, root, err := parseXML(wresult, "wresult")
	if err != nil {
		return nil, err
	}
	if err := assertUniqueIDs(root); err != nil {
		return nil, err
	}
	rstr, trust, trustVersion, err := responseOf(root)
	if err != nil {
		return nil, err
	}
	tokenTypeEl, err := child(rstr, trust, "TokenType")
	if err != nil {
		return nil, err
	}
	tokenType := textOf(tokenTypeEl)
	if tokenType != "" && !isSaml2Token(tokenType) {
		return nil, malformed("the response carries a token of type " + tokenType + "; this relying party accepts SAML 2.0 assertions only")
	}
	applies := append(children(rstr, NSWSP, "AppliesTo"), children(rstr, NSWSP15, "AppliesTo")...)
	if len(applies) > 1 {
		return nil, malformed("the response has more than one AppliesTo")
	}
	if len(applies) == 1 {
		scopes := wsaAddresses(applies[0])
		if len(scopes) > 0 {
			found := false
			for _, scope := range scopes {
				if scope == ctx.Realm {
					found = true
					break
				}
			}
			if !found {
				return nil, invalid("the response applies to " + strings.Join(scopes, ", ") + ", not to " + ctx.Realm)
			}
		}
	}
	lifetime, err := child(rstr, trust, "Lifetime")
	if err != nil {
		return nil, err
	}
	var expires *time.Time
	if lifetime != nil {
		raw := textOf(firstChild(lifetime, NSWSU, "Expires"))
		expires, err = parseInstant(raw, "the response's Lifetime Expires")
		if err != nil {
			return nil, err
		}
	}
	if expires != nil && millis(*expires) <= nowMs-skew {
		return nil, invalid("the response expired at " + isoTime(*expires))
	}
	requested := children(rstr, trust, "RequestedSecurityToken")
	if len(requested) != 1 {
		return nil, malformed("the response holds " + itoa(len(requested)) + " RequestedSecurityToken elements; exactly one is accepted")
	}
	tokens := elementChildren(requested[0])
	if len(tokens) != 1 {
		return nil, malformed("the RequestedSecurityToken holds " + itoa(len(tokens)) + " tokens; exactly one is accepted")
	}
	token := tokens[0]
	encrypted := false
	var assertion *etree.Element
	if isEl(token, NSSaml, "Assertion") {
		if ctx.WantAssertionsEncrypted {
			return nil, invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on")
		}
		assertion = token
	} else if isEl(token, NSSaml, "EncryptedAssertion") || isEl(token, NSXenc, "EncryptedData") {
		if ctx.DecryptionKey == nil {
			return nil, fail("decryption", "the assertion is encrypted, and this relying party has no privateKey to decrypt it with")
		}
		encrypted = true
		plain, err := decryptElement(token, ctx.DecryptionKey)
		if err != nil {
			return nil, err
		}
		_, assertionRoot, err := parseXML(plain, "the decrypted assertion")
		if err != nil {
			return nil, err
		}
		if err := assertUniqueIDs(assertionRoot); err != nil {
			return nil, err
		}
		assertion = assertionRoot
		if isEl(assertion, NSSaml1, "Assertion") {
			return nil, malformed("the encrypted token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only")
		}
		if !isEl(assertion, NSSaml, "Assertion") {
			return nil, invalid("the encrypted token does not hold a SAML 2.0 Assertion")
		}
	} else if isEl(token, NSSaml1, "Assertion") {
		return nil, malformed("the token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only. Ask for SAML 2.0 (requestTokenType, the default), or configure the identity provider to issue it to this realm")
	} else {
		return nil, malformed("the RequestedSecurityToken holds a <" + token.Tag + ">, not a SAML 2.0 assertion")
	}
	signed, err := verifySigned(assertion, ctx.IdPCertificates, "the assertion")
	if err != nil {
		return nil, err
	}
	if signed == "" {
		return nil, invalid("the assertion is not signed; in WS-Federation its signature is the only one, so it is required")
	}
	_, assertion, err = parseXML(signed, "the signed assertion")
	if err != nil {
		return nil, err
	}
	if version, _ := attr(assertion, "Version"); version != "2.0" {
		return nil, invalid("the assertion is not version 2.0")
	}
	assertionID, _ := attr(assertion, "ID")
	if assertionID == "" {
		return nil, invalid("the assertion has no ID")
	}
	issuer, err := child(assertion, NSSaml, "Issuer")
	if err != nil {
		return nil, err
	}
	if issuer == nil {
		return nil, invalid("the assertion has no Issuer")
	}
	if format, ok := attr(issuer, "Format"); ok && format != "" && format != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" {
		return nil, invalid("the assertion's Issuer has the Format " + format)
	}
	if textOf(issuer) != ctx.IdPEntityID {
		return nil, invalid("the assertion was issued by " + textOf(issuer) + ", not by " + ctx.IdPEntityID)
	}
	subject, err := child(assertion, NSSaml, "Subject")
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, invalid("the assertion has no Subject")
	}
	nameID, err := child(subject, NSSaml, "NameID")
	if err != nil {
		return nil, err
	}
	encryptedID, err := child(subject, NSSaml, "EncryptedID")
	if err != nil {
		return nil, err
	}
	if nameID == nil && encryptedID != nil {
		if ctx.DecryptionKey == nil {
			return nil, fail("decryption", "the NameID is encrypted, and this relying party has no privateKey to decrypt it with")
		}
		plain, err := decryptElement(encryptedID, ctx.DecryptionKey)
		if err != nil {
			return nil, err
		}
		_, nameID, err = parseXML(plain, "the decrypted NameID")
		if err != nil {
			return nil, err
		}
		if !isEl(nameID, NSSaml, "NameID") {
			return nil, invalid("the EncryptedID does not hold a NameID")
		}
	}
	if nameID == nil || textOf(nameID) == "" {
		return nil, invalid("the assertion's Subject has no NameID")
	}
	conditions, err := child(assertion, NSSaml, "Conditions")
	if err != nil {
		return nil, err
	}
	if conditions == nil {
		return nil, invalid("the assertion has no Conditions, so it names no audience")
	}
	notBefore, err := attrInstant(conditions, "NotBefore", "Conditions NotBefore")
	if err != nil {
		return nil, err
	}
	notOnOrAfter, err := attrInstant(conditions, "NotOnOrAfter", "Conditions NotOnOrAfter")
	if err != nil {
		return nil, err
	}
	var reasons []string
	var confirmedUntil *time.Time
	for _, confirmation := range children(subject, NSSaml, "SubjectConfirmation") {
		method, _ := attr(confirmation, "Method")
		if method != CMBearer {
			reasons = append(reasons, "method "+method)
			continue
		}
		data, err := child(confirmation, NSSaml, "SubjectConfirmationData")
		if err != nil {
			return nil, err
		}
		if data == nil {
			if notOnOrAfter == nil {
				reasons = append(reasons, "no SubjectConfirmationData, and no Conditions NotOnOrAfter to bound it")
				continue
			}
			confirmedUntil = notOnOrAfter
			break
		}
		recipient, hasRecipient := attr(data, "Recipient")
		until, err := attrInstant(data, "NotOnOrAfter", "SubjectConfirmationData NotOnOrAfter")
		if err != nil {
			return nil, err
		}
		if until == nil {
			until = notOnOrAfter
		}
		if hasRecipient && recipient != ctx.ReplyURL {
			reasons = append(reasons, "Recipient "+recipient)
		} else if until == nil {
			reasons = append(reasons, "no NotOnOrAfter, on the confirmation or the Conditions")
		} else if millis(*until) <= nowMs-skew {
			reasons = append(reasons, "expired at "+isoTime(*until))
		} else if _, has := attr(data, "NotBefore"); has {
			reasons = append(reasons, "a NotBefore, which a bearer confirmation must not have")
		} else if irt, has := attr(data, "InResponseTo"); has {
			reasons = append(reasons, "InResponseTo "+irt+", which answers a SAML request, not a WS-Federation sign-in")
		} else {
			confirmedUntil = until
			break
		}
	}
	if confirmedUntil == nil {
		why := strings.Join(reasons, "; ")
		if why == "" {
			why = "there is none"
		}
		return nil, invalid("no bearer SubjectConfirmation of the assertion fits: " + why)
	}
	if notBefore != nil && millis(*notBefore) > nowMs+skew {
		return nil, invalid("the assertion is not valid before " + isoTime(*notBefore))
	}
	if notOnOrAfter != nil && millis(*notOnOrAfter) <= nowMs-skew {
		return nil, invalid("the assertion expired at " + isoTime(*notOnOrAfter))
	}
	restrictions := children(conditions, NSSaml, "AudienceRestriction")
	if len(restrictions) == 0 {
		return nil, invalid("the assertion has no AudienceRestriction")
	}
	for _, restriction := range restrictions {
		ok := false
		for _, audience := range children(restriction, NSSaml, "Audience") {
			if textOf(audience) == ctx.Realm {
				ok = true
				break
			}
		}
		if !ok {
			return nil, invalid("the assertion is not for " + ctx.Realm)
		}
	}
	authnAll := children(assertion, NSSaml, "AuthnStatement")
	if len(authnAll) == 0 {
		return nil, invalid("the assertion has no AuthnStatement")
	}
	authn := authnAll[0]
	authnInstant, err := attrInstant(authn, "AuthnInstant", "AuthnInstant")
	if err != nil {
		return nil, err
	}
	if authnInstant == nil {
		return nil, invalid("the AuthnStatement has no AuthnInstant")
	}
	sessionNot, err := attrInstant(authn, "SessionNotOnOrAfter", "SessionNotOnOrAfter")
	if err != nil {
		return nil, err
	}
	if sessionNot != nil && millis(*sessionNot) <= nowMs-skew {
		return nil, invalid("the identity provider's session has already ended")
	}
	contextEl, err := child(authn, NSSaml, "AuthnContext")
	if err != nil {
		return nil, err
	}
	classRef := ""
	if contextEl != nil {
		classRef = textOf(firstChild(contextEl, NSSaml, "AuthnContextClassRef"))
	}
	attributes := map[string][]string{}
	friendly := map[string]string{}
	for _, statement := range children(assertion, NSSaml, "AttributeStatement") {
		var decrypted []*etree.Element
		for _, encryptedAttr := range children(statement, NSSaml, "EncryptedAttribute") {
			if ctx.DecryptionKey == nil {
				return nil, fail("decryption", "an attribute is encrypted, and this relying party has no privateKey to decrypt it with")
			}
			plain, err := decryptElement(encryptedAttr, ctx.DecryptionKey)
			if err != nil {
				return nil, err
			}
			_, element, err := parseXML(plain, "the decrypted attribute")
			if err != nil {
				return nil, err
			}
			if !isEl(element, NSSaml, "Attribute") {
				return nil, invalid("an EncryptedAttribute does not hold an Attribute")
			}
			decrypted = append(decrypted, element)
		}
		attrs := append(children(statement, NSSaml, "Attribute"), decrypted...)
		for _, attribute := range attrs {
			name, _ := attr(attribute, "Name")
			if name == "" {
				continue
			}
			var values []string
			for _, value := range children(attribute, NSSaml, "AttributeValue") {
				values = append(values, textContent(value))
			}
			attributes[name] = append(attributes[name], values...)
			if friendlyName, ok := attr(attribute, "FriendlyName"); ok && friendlyName != "" {
				friendly[name] = friendlyName
			}
		}
	}
	keep := millis(*confirmedUntil)
	if notOnOrAfter != nil && millis(*notOnOrAfter) > keep {
		keep = millis(*notOnOrAfter)
	}
	keep += skew
	keepUntil := time.UnixMilli(keep).UTC()
	replayID := ctx.IdPEntityID + " " + assertionID
	if ctx.Replay == nil {
		ctx.Replay = NewMemoryReplayCache(0)
	}
	recorded, err := ctx.Replay.CheckAndRecord(replayID, keepUntil)
	if err != nil {
		return nil, failCause("replay", err.Error(), err)
	}
	if recorded {
		return nil, fail("replay", "the assertion "+assertionID+" has been accepted before")
	}
	login := &Login{
		NameID:                 textOf(nameID),
		AuthnInstant:           *authnInstant,
		Attributes:             attributes,
		AttributeFriendlyNames: friendly,
		Issuer:                 ctx.IdPEntityID,
		Realm:                  ctx.Realm,
		TrustVersion:           trustVersion,
		Encrypted:              encrypted,
		AssertionID:            assertionID,
		NotOnOrAfter:           *confirmedUntil,
	}
	if v, ok := attr(nameID, "Format"); ok && v != "" {
		login.NameIDFormat = &v
	}
	if v, ok := attr(nameID, "NameQualifier"); ok && v != "" {
		login.NameQualifier = &v
	}
	if v, ok := attr(nameID, "SPNameQualifier"); ok && v != "" {
		login.SPNameQualifier = &v
	}
	if v, ok := attr(authn, "SessionIndex"); ok && v != "" {
		login.SessionIndex = &v
	}
	if sessionNot != nil {
		login.SessionNotOnOrAfter = sessionNot
	}
	if classRef != "" {
		login.AuthnContextClassRef = &classRef
	}
	return login, nil
}

func firstChild(el *etree.Element, ns, local string) *etree.Element {
	found := children(el, ns, local)
	if len(found) == 0 {
		return nil
	}
	return found[0]
}
