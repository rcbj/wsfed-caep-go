// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed_test

import (
	"encoding/base64"
	"github.com/rcbj/wsfed-caep-go/wsfed"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rcbj/wsfed-caep-go/stubidp"
)

func mustRP(t *testing.T, config map[string]any) *wsfed.RelyingParty {
	t.Helper()
	rp, err := wsfed.Create(config, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func rejects(t *testing.T, err error, code, pattern string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	got, ok := err.(*wsfed.WsFedError)
	if !ok {
		t.Fatalf("%T %v", err, err)
	}
	if got.Code != code {
		t.Fatalf("code %s, want %s: %s", got.Code, code, got.Error())
	}
	if pattern != "" && !regexp.MustCompile(pattern).MatchString(got.Error()) {
		t.Fatalf("pattern %s not in %s", pattern, got.Error())
	}
}

func cfg(extra map[string]any, meta *stubidp.MetaOptions) map[string]any {
	body := map[string]any{
		"realm":       stubidp.Realm,
		"replyUrl":    stubidp.Reply,
		"privateKey":  stubidp.RPKey,
		"certificate": stubidp.RPCert,
		"idpMetadata": stubidp.IdPMetadata(meta),
	}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

func str(value string) *string { return &value }

func sameConfig(a, b *wsfed.Resolved) bool {
	return a.Realm == b.Realm && a.ReplyURL == b.ReplyURL && a.IdPMetadata == b.IdPMetadata &&
		a.ClockSkewMs == b.ClockSkewMs && a.WantAssertionsEncrypted == b.WantAssertionsEncrypted &&
		a.AllowUnsolicited == b.AllowUnsolicited && a.RequestTokenType == b.RequestTokenType &&
		a.IdPCA == b.IdPCA && a.IdPEntityID == b.IdPEntityID && a.PrivateKey == nil && b.PrivateKey == nil
}

func hasToken(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func post(rp *wsfed.RelyingParty, result string, requestID, wctx *string, ids []string) (*wsfed.Login, error) {
	body := map[string]string{"wa": "wsignin1.0", "wresult": result}
	if wctx == nil && requestID != nil {
		value := "id=" + *requestID
		wctx = &value
	}
	if wctx != nil {
		body["wctx"] = *wctx
	}
	if ids == nil && requestID != nil {
		ids = []string{*requestID}
	}
	return rp.HandleReply(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: body}, ids)
}

func qparams(raw string) map[string]string {
	parsed, _ := url.Parse(raw)
	out := map[string]string{}
	for key, values := range parsed.Query() {
		out[key] = values[0]
	}
	return out
}

func TestConfigurationRequiresRealmReplyAndAMatchingKey(t *testing.T) {
	_, err := wsfed.Create(cfg(map[string]any{"realm": ""}, nil), "")
	rejects(t, err, "config", "realm")
	_, err = wsfed.Create(cfg(map[string]any{"replyUrl": "/wsfed"}, nil), "")
	rejects(t, err, "config", "absolute")
	_, err = wsfed.Create(cfg(map[string]any{"certificate": stubidp.IdPCert}, nil), "")
	rejects(t, err, "config", "not for the private key")
	_, err = wsfed.Create(map[string]any{"realm": stubidp.Realm, "replyUrl": stubidp.Reply, "idpMetadata": stubidp.IdPMetadata(nil), "privateKey": stubidp.RPKey}, "")
	rejects(t, err, "config", "together")
	_, err = wsfed.Create(map[string]any{"realm": stubidp.Realm, "replyUrl": stubidp.Reply, "idpMetadata": stubidp.IdPMetadata(nil), "wantAssertionsEncrypted": true}, "")
	rejects(t, err, "config", "needs privateKey")
	keyless := mustRP(t, map[string]any{"realm": stubidp.Realm, "replyUrl": stubidp.Reply, "idpMetadata": stubidp.IdPMetadata(nil)})
	if strings.Contains(keyless.Metadata(), "KeyDescriptor") {
		t.Fatal("keyless metadata named a key")
	}
}

func TestSignalsOmittedOrTrueIsLeftOff(t *testing.T) {
	base := map[string]any{"realm": stubidp.Realm, "replyUrl": stubidp.Reply, "idpMetadata": "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml"}
	omitted, err := wsfed.ResolveConfig(base, "")
	if err != nil {
		t.Fatal(err)
	}
	if omitted.SignalsSet {
		t.Fatal("omitted signals was recorded")
	}
	if omitted.Realm != stubidp.Realm || omitted.ReplyURL != stubidp.Reply || !omitted.RequestTokenType {
		t.Fatalf("%+v", omitted)
	}
	on := map[string]any{}
	for key, value := range base {
		on[key] = value
	}
	on["signals"] = true
	resolved, err := wsfed.ResolveConfig(on, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.SignalsSet || !sameConfig(resolved, omitted) {
		t.Fatal("signals true changed the resolved config")
	}
}

func TestSignalsFalseIsRecorded(t *testing.T) {
	base := map[string]any{"realm": stubidp.Realm, "replyUrl": stubidp.Reply, "idpMetadata": "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml"}
	offMap := map[string]any{}
	for key, value := range base {
		offMap[key] = value
	}
	offMap["signals"] = false
	off, err := wsfed.ResolveConfig(offMap, "")
	if err != nil {
		t.Fatal(err)
	}
	if !off.SignalsSet || off.Signals {
		t.Fatal("signals false was not recorded")
	}
	omitted, err := wsfed.ResolveConfig(base, "")
	if err != nil {
		t.Fatal(err)
	}
	if !sameConfig(off, omitted) || off.IdPMetadata != base["idpMetadata"] {
		t.Fatal("signals false changed the rest of the config")
	}
}

func TestSignalsMustBeTrueOrFalse(t *testing.T) {
	_, err := wsfed.ResolveConfig(map[string]any{"realm": stubidp.Realm, "replyUrl": stubidp.Reply, "idpMetadata": "https://idp.example/metadata", "signals": "no"}, "")
	rejects(t, err, "config", "")
	if err.Error() != "signals must be true or false" {
		t.Fatal(err)
	}
}

func TestReadsTheSecurityTokenServiceRole(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	if rp.Idp.EntityID != stubidp.IdPEntity || rp.Idp.PassiveRequestorEndpoint != stubidp.Passive {
		t.Fatalf("%+v", rp.Idp)
	}
	if !hasToken(rp.Idp.TokenTypesOffered, wsfed.SAML2Token) {
		t.Fatal(rp.Idp.TokenTypesOffered)
	}
	if len(rp.Idp.SigningCertificates) != 1 {
		t.Fatal(len(rp.Idp.SigningCertificates))
	}
}

func TestXsiTypeAndIdpRoleFallback(t *testing.T) {
	if mustRP(t, cfg(nil, &stubidp.MetaOptions{FedPrefix: "wsfed"})).Idp.PassiveRequestorEndpoint != stubidp.Passive {
		t.Fatal("prefix")
	}
	if len(mustRP(t, cfg(nil, &stubidp.MetaOptions{KeyIn: "idpsso"})).Idp.SigningCertificates) != 1 {
		t.Fatal("fallback key")
	}
}

func TestRefusesMetadataWithoutAnSTSOrSAML2(t *testing.T) {
	_, err := wsfed.Create(cfg(nil, &stubidp.MetaOptions{NoSTS: true}), "")
	rejects(t, err, "metadata", "SecurityTokenServiceType")
	_, err = wsfed.Create(cfg(nil, &stubidp.MetaOptions{TokenTypes: []string{"urn:oasis:names:tc:SAML:1.0:assertion"}}), "")
	rejects(t, err, "metadata", "no SAML 2.0")
}

func TestWritesApplicationServiceMetadata(t *testing.T) {
	xml := mustRP(t, cfg(nil, nil)).Metadata()
	if !strings.Contains(xml, `entityID="`+stubidp.Realm+`"`) {
		t.Fatal(xml)
	}
	if !strings.Contains(xml, `xsi:type="fed:ApplicationServiceType"`) {
		t.Fatal(xml)
	}
	if !strings.Contains(xml, "<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>"+stubidp.Reply+"</wsa:Address>") {
		t.Fatal(xml)
	}
	if !strings.Contains(xml, "<fed:TargetScopes><wsa:EndpointReference><wsa:Address>"+stubidp.Realm+"</wsa:Address>") {
		t.Fatal(xml)
	}
	if !regexp.MustCompile(`<md:KeyDescriptor use="encryption">[\s\S]*xmlenc11#aes256-gcm[\s\S]*</md:KeyDescriptor>`).MatchString(xml) {
		t.Fatal(xml)
	}
}

func TestSigninNamesRealmReplyWctxAndSAML2(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	req, err := rp.Login(&wsfed.LoginOptions{RelayState: str("/home é")})
	if err != nil {
		t.Fatal(err)
	}
	params := qparams(req.URL)
	parsed, _ := url.Parse(req.URL)
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != stubidp.Passive {
		t.Fatal(req.URL)
	}
	if params["wa"] != "wsignin1.0" || params["wtrealm"] != stubidp.Realm || params["wreply"] != stubidp.Reply {
		t.Fatal(params)
	}
	wctx, _ := url.ParseQuery(params["wctx"])
	if wctx.Get("id") != req.ID || wctx.Get("ru") != "/home é" {
		t.Fatal(params["wctx"])
	}
	if !strings.Contains(params["wreq"], "<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>") {
		t.Fatal(params["wreq"])
	}
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`).MatchString(params["wct"]) {
		t.Fatal(params["wct"])
	}
	if _, ok := params["wfresh"]; ok {
		t.Fatal("wfresh")
	}
}

func TestForceAuthnAndProtocolParams(t *testing.T) {
	rp := mustRP(t, cfg(map[string]any{"requestTokenType": false}, nil))
	fresh := 0
	req, err := rp.Login(&wsfed.LoginOptions{ForceAuthn: true, AuthenticationMethod: "http://schemas.microsoft.com/claims/multipleauthn", HomeRealm: "urn:partner", Params: map[string]string{"login_hint": "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	params := qparams(req.URL)
	if params["wfresh"] != "0" || params["wauth"] != "http://schemas.microsoft.com/claims/multipleauthn" || params["whr"] != "urn:partner" || params["login_hint"] != "alice" {
		t.Fatal(params)
	}
	if _, ok := params["wreq"]; ok {
		t.Fatal("wreq")
	}
	_, err = rp.Login(&wsfed.LoginOptions{Params: map[string]string{"wtrealm": "urn:evil"}})
	rejects(t, err, "config", "protocol's own")
	_, err = rp.Login(&wsfed.LoginOptions{RelayState: str(strings.Repeat("x", 1025))})
	rejects(t, err, "config", "1024 bytes")
	_ = fresh
}

func TestSignoutRequest(t *testing.T) {
	params := qparams(mustLogout(t, mustRP(t, cfg(nil, nil)), "https://rp.test/"))
	if params["wa"] != "wsignout1.0" || params["wtrealm"] != stubidp.Realm || params["wreply"] != "https://rp.test/" {
		t.Fatal(params)
	}
}

func mustLogout(t *testing.T, rp *wsfed.RelyingParty, reply string) string {
	t.Helper()
	raw, err := rp.Logout(reply)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignedAssertionInA2005Response(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	req, err := rp.Login(&wsfed.LoginOptions{RelayState: str("/home")})
	if err != nil {
		t.Fatal(err)
	}
	result, err := stubidp.WResult(nil)
	if err != nil {
		t.Fatal(err)
	}
	who, err := post(rp, result, &req.ID, &req.Wctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if who.NameID != "alice-1234" || who.NameIDFormat == nil || *who.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		t.Fatalf("%+v", who)
	}
	if who.SessionIndex == nil || *who.SessionIndex != "_session1" || who.RelayState == nil || *who.RelayState != "/home" || who.RequestID == nil || *who.RequestID != req.ID {
		t.Fatalf("%+v %v %v", who.SessionIndex, who.RelayState, who.RequestID)
	}
	if who.TrustVersion != "2005/02" || who.Realm != stubidp.Realm || who.Encrypted {
		t.Fatal(who.TrustVersion, who.Encrypted)
	}
	if strings.Join(who.Attributes["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"], ",") != "staff,admins" {
		t.Fatal(who.Attributes)
	}
	if who.AttributeFriendlyNames["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] != "mail" {
		t.Fatal(who.AttributeFriendlyNames)
	}
	if who.AuthnContextClassRef == nil || *who.AuthnContextClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" {
		t.Fatal(who.AuthnContextClassRef)
	}
}

func TestTrust13AndARawFormBody(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	result, err := stubidp.WResult(&stubidp.WResultOptions{Trust: "1.3"})
	if err != nil {
		t.Fatal(err)
	}
	who, err := post(rp, result, str("_r"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if who.TrustVersion != "1.3" {
		t.Fatal(who.TrustVersion)
	}
	signed, err := stubidp.WResult(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := url.Values{"wa": {"wsignin1.0"}, "wresult": {signed}, "wctx": {"id=_s"}}.Encode()
	who, err = rp.HandleReply(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: raw}, []string{"_x", "_s"})
	if err != nil {
		t.Fatal(err)
	}
	if who.NameID != "alice-1234" {
		t.Fatal(who.NameID)
	}
}

func TestRecipientOptionalAndChecked(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	made, err := stubidp.SignedAssertion(&stubidp.AssertionOptions{Recipient: str("")})
	if err != nil {
		t.Fatal(err)
	}
	token := made.XML
	result, err := stubidp.WResult(&stubidp.WResultOptions{Token: &token})
	if err != nil {
		t.Fatal(err)
	}
	who, err := post(rp, result, str("_r"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if who.NameID != "alice-1234" {
		t.Fatal(who.NameID)
	}
	made, err = stubidp.SignedAssertion(&stubidp.AssertionOptions{Recipient: str("https://other.test/wsfed")})
	if err != nil {
		t.Fatal(err)
	}
	token = made.XML
	result, err = stubidp.WResult(&stubidp.WResultOptions{Token: &token})
	if err != nil {
		t.Fatal(err)
	}
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "Recipient")
}

func TestBareBearerConfirmation(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	made, err := stubidp.SignedAssertion(&stubidp.AssertionOptions{BareConfirmation: true})
	if err != nil {
		t.Fatal(err)
	}
	token := made.XML
	result, err := stubidp.WResult(&stubidp.WResultOptions{Token: &token})
	if err != nil {
		t.Fatal(err)
	}
	who, err := post(rp, result, str("_r"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if who.NameID != "alice-1234" || !who.NotOnOrAfter.After(time.Now()) {
		t.Fatal(who.NotOnOrAfter)
	}
	made, err = stubidp.SignedAssertion(&stubidp.AssertionOptions{BareConfirmation: true, NotOnOrAfter: -120 * time.Second, NotOnOrAfterSet: true})
	if err != nil {
		t.Fatal(err)
	}
	token = made.XML
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &token})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "expired")
	made, err = stubidp.SignedAssertion(&stubidp.AssertionOptions{BareConfirmation: true, NoConditionsExpiry: true})
	if err != nil {
		t.Fatal(err)
	}
	token = made.XML
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &token})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "nothing|no Conditions NotOnOrAfter")
}

func TestUnsignedAssertionIsRefused(t *testing.T) {
	made := stubidp.AssertionXML(nil)
	token := made.XML
	result, err := stubidp.WResult(&stubidp.WResultOptions{Token: &token})
	if err != nil {
		t.Fatal(err)
	}
	_, err = post(mustRP(t, cfg(nil, nil)), result, str("_r"), nil, nil)
	rejects(t, err, "validation", "not signed")
}

func TestAlteredOrWrongKeyIsRefused(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	made, err := stubidp.SignedAssertion(nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := stubidp.WResult(&stubidp.WResultOptions{Token: str(strings.Replace(made.XML, "alice-1234", "mallory", 1))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "signature", "")
	plain := stubidp.AssertionXML(nil)
	signed, err := stubidp.SignXML(plain.XML, plain.ID, stubidp.RPKey, stubidp.RPCert)
	if err != nil {
		t.Fatal(err)
	}
	result, err = stubidp.WResult(&stubidp.WResultOptions{Token: &signed})
	if err != nil {
		t.Fatal(err)
	}
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "signature", "does not verify")
}

func TestSignatureWrapping(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	signed, err := stubidp.SignedAssertion(nil)
	if err != nil {
		t.Fatal(err)
	}
	forged := stubidp.AssertionXML(&stubidp.AssertionOptions{NameID: "mallory"})
	both := forged.XML + signed.XML
	result, err := stubidp.WResult(&stubidp.WResultOptions{Token: &both})
	if err != nil {
		t.Fatal(err)
	}
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "message", "exactly one")
	hidden := regexp.MustCompile(`ID="[^"]+"`).ReplaceAllString(forged.XML, `ID="`+signed.ID+`"`)
	hidden = strings.Replace(hidden, "</saml:Assertion>", "<saml:Advice>"+signed.XML+"</saml:Advice></saml:Assertion>", 1)
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &hidden})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "signature", "two elements")
	decoy, _ := stubidp.WResult(&stubidp.WResultOptions{Token: &signed.XML})
	decoy = strings.Replace(decoy, "<t:Lifetime>", `<t:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="`+signed.ID+`">`, 1)
	_, err = post(rp, decoy, str("_r"), nil, nil)
	rejects(t, err, "signature", "two elements")
	sig := regexp.MustCompile(`<ds:Signature[\s\S]*</ds:Signature>`).FindString(signed.XML)
	moved := regexp.MustCompile(`(</saml:Issuer>)`).ReplaceAllString(forged.XML, "${1}"+sig)
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &moved})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "signature", "refers to")
}

func TestWrongRealmIssuerOrExpiry(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	made, _ := stubidp.SignedAssertion(&stubidp.AssertionOptions{Audience: str("https://other.test/")})
	result, _ := stubidp.WResult(&stubidp.WResultOptions{Token: &made.XML})
	_, err := post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "not for")
	made, _ = stubidp.SignedAssertion(&stubidp.AssertionOptions{Issuer: "https://evil.test"})
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &made.XML})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "issued by")
	made, _ = stubidp.SignedAssertion(&stubidp.AssertionOptions{NotOnOrAfter: -120 * time.Second, NotOnOrAfterSet: true})
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &made.XML})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "expired")
	result, _ = stubidp.WResult(&stubidp.WResultOptions{AppliesTo: "https://other.test/"})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "applies to")
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Expires: -120 * time.Second, ExpiresSet: true})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "response expired")
}

func TestInResponseToIsRefused(t *testing.T) {
	made, err := stubidp.SignedAssertion(&stubidp.AssertionOptions{InResponseTo: "_samlreq"})
	if err != nil {
		t.Fatal(err)
	}
	result, _ := stubidp.WResult(&stubidp.WResultOptions{Token: &made.XML})
	_, err = post(mustRP(t, cfg(nil, nil)), result, str("_r"), nil, nil)
	rejects(t, err, "validation", "InResponseTo")
}

func TestSaml11AndNonTrustAreRefused(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	token := stubidp.Saml11()
	result, _ := stubidp.WResult(&stubidp.WResultOptions{Token: &token, TokenType: "urn:oasis:names:tc:SAML:2.0:assertion"})
	_, err := post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "message", `SAML 1\.1`)
	result, _ = stubidp.WResult(&stubidp.WResultOptions{TokenType: "urn:oasis:names:tc:SAML:1.0:assertion"})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "message", "SAML 2.0 assertions only")
	made, _ := stubidp.SignedAssertion(nil)
	_, err = post(rp, made.XML, str("_r"), nil, nil)
	rejects(t, err, "message", "not a WS-Trust")
	result, _ = stubidp.WResult(nil)
	_, err = post(rp, `<!DOCTYPE x [<!ENTITY e "x">]>`+result, str("_r"), nil, nil)
	rejects(t, err, "xml", "DOCTYPE")
}

func TestUnsolicitedAndUnknownRequests(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	result, err := stubidp.WResult(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = post(rp, result, str("_other"), str("id=_r"), nil)
	rejects(t, err, "validation", "not a sign-in this browser")
	_, err = post(rp, result, nil, str("id=_r"), []string{})
	rejects(t, err, "validation", "not a sign-in this browser")
	_, err = post(rp, result, nil, nil, []string{})
	rejects(t, err, "validation", "unsolicited")
	open := mustRP(t, cfg(map[string]any{"allowUnsolicited": true}, nil))
	who, err := post(open, result, nil, str("ru=%2Fthere"), []string{})
	if err != nil {
		t.Fatal(err)
	}
	if who.RequestID != nil || who.RelayState == nil || *who.RelayState != "/there" {
		t.Fatalf("%v %v", who.RequestID, who.RelayState)
	}
}

func TestReplay(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	result, err := stubidp.WResult(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := post(rp, result, str("_r"), nil, nil); err != nil {
		t.Fatal(err)
	}
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "replay", "")
}

func TestDecryptsEncryptedAssertions(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	for _, name := range []string{"aes-256-gcm", "aes-128-cbc"} {
		made, err := stubidp.SignedAssertion(nil)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := stubidp.Encrypt(made.XML, name, "", "")
		if err != nil {
			t.Fatal(err)
		}
		result, err := stubidp.WResult(&stubidp.WResultOptions{Token: &enc})
		if err != nil {
			t.Fatal(err)
		}
		who, err := post(rp, result, str("_r"), nil, nil)
		if err != nil {
			t.Fatal(name, err)
		}
		if who.NameID != "alice-1234" || !who.Encrypted {
			t.Fatal(name, who.NameID, who.Encrypted)
		}
	}
	made, _ := stubidp.SignedAssertion(nil)
	enc, err := stubidp.Encrypt(made.XML, "aes-256-gcm", "oaep256", "none")
	if err != nil {
		t.Fatal(err)
	}
	result, _ := stubidp.WResult(&stubidp.WResultOptions{Token: &enc})
	who, err := post(rp, result, str("_r"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !who.Encrypted {
		t.Fatal("expected encrypted")
	}
}

func TestWantAssertionsEncryptedAndTamperedCiphertext(t *testing.T) {
	rp := mustRP(t, cfg(map[string]any{"wantAssertionsEncrypted": true}, nil))
	result, _ := stubidp.WResult(nil)
	_, err := post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "not encrypted")
	plain := stubidp.AssertionXML(nil)
	enc, err := stubidp.Encrypt(plain.XML, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &enc})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "validation", "not signed")
	made, _ := stubidp.SignedAssertion(nil)
	enc, _ = stubidp.Encrypt(made.XML, "", "", "")
	values := regexp.MustCompile(`<xenc:CipherValue>([^<]+)</xenc:CipherValue>`).FindAllStringSubmatch(enc, -1)
	last := values[len(values)-1][1]
	raw, err := base64.StdEncoding.DecodeString(last)
	if err != nil {
		t.Fatal(err)
	}
	raw[20] ^= 1
	replaced := strings.Replace(enc, last, base64.StdEncoding.EncodeToString(raw), 1)
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &replaced})
	_, err = post(rp, result, str("_r"), nil, nil)
	rejects(t, err, "decryption", "")
}

func TestEncryptedAttributeAndMissingKey(t *testing.T) {
	keyless := mustRP(t, map[string]any{"realm": stubidp.Realm, "replyUrl": stubidp.Reply, "idpMetadata": stubidp.IdPMetadata(nil)})
	made, _ := stubidp.SignedAssertion(nil)
	enc, err := stubidp.Encrypt(made.XML, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, _ := stubidp.WResult(&stubidp.WResultOptions{Token: &enc})
	_, err = post(keyless, result, str("_r"), nil, nil)
	rejects(t, err, "decryption", "no privateKey")
	rp := mustRP(t, cfg(nil, nil))
	secret, err := stubidp.Encrypt(`<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="employeeNumber"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>`, "aes-256-gcm", "oaep256", "EncryptedAttribute")
	if err != nil {
		t.Fatal(err)
	}
	plain := stubidp.AssertionXML(&stubidp.AssertionOptions{ExtraAttributes: secret})
	signed, err := stubidp.SignXML(plain.XML, plain.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, _ = stubidp.WResult(&stubidp.WResultOptions{Token: &signed})
	who, err := post(rp, result, str("_r"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(who.Attributes["employeeNumber"], ",") != "E-42" {
		t.Fatal(who.Attributes)
	}
}

func TestReplyURLRefusesGetWrongWaAndWresultptr(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	result, _ := stubidp.WResult(nil)
	_, err := rp.HandleReply(wsfed.ReplyRequest{Method: "GET", URL: "/wsfed?wa=wsignin1.0&wresult=" + url.QueryEscape(result)}, nil)
	rejects(t, err, "message", "POSTed")
	_, err = rp.HandleReply(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: map[string]string{"wa": "wattr1.0", "wresult": result}}, nil)
	rejects(t, err, "message", "not wsignin1.0")
	_, err = rp.HandleReply(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: map[string]string{"wa": "wsignin1.0", "wresultptr": "https://evil.test/"}}, nil)
	rejects(t, err, "message", "wresultptr")
	_, err = rp.HandleReply(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: map[string]string{"wa": "wsignin1.0"}}, nil)
	rejects(t, err, "message", "no wresult")
}

func TestSignOutCleanup(t *testing.T) {
	rp := mustRP(t, cfg(nil, nil))
	if !rp.IsSignOutCleanup(wsfed.ReplyRequest{Method: "GET", URL: "/wsfed?wa=wsignoutcleanup1.0"}) {
		t.Fatal("cleanup")
	}
	if !rp.IsSignOutCleanup(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: "wa=wsignout1.0"}) {
		t.Fatal("signout")
	}
	if rp.IsSignOutCleanup(wsfed.ReplyRequest{Method: "POST", URL: "/wsfed", Body: map[string]string{"wa": "wsignin1.0"}}) {
		t.Fatal("signin")
	}
	_, err := rp.HandleReply(wsfed.ReplyRequest{Method: "GET", URL: "/wsfed?wa=wsignoutcleanup1.0"}, nil)
	rejects(t, err, "message", "sign-out")
}

func TestStatusSuccessConstant(t *testing.T) {
	if wsfed.StatusSuccess != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Fatal(wsfed.StatusSuccess)
	}
	if wsfed.RSASHA256 != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		t.Fatal(wsfed.RSASHA256)
	}
	if wsfed.DefaultSubjectAttribute != "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" {
		t.Fatal(wsfed.DefaultSubjectAttribute)
	}
}
