// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"

	"github.com/beevik/etree"
)

var encryptionMethods = []string{
	"http://www.w3.org/2009/xmlenc11#aes256-gcm",
	"http://www.w3.org/2009/xmlenc11#aes128-gcm",
	"http://www.w3.org/2009/xmlenc11#rsa-oaep",
	"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
}

// IdPMetadata is the security token service this relying party talks to.
type IdPMetadata struct {
	EntityID                 string
	PassiveRequestorEndpoint string
	TokenTypesOffered        []string
	SigningCertificates      []*x509.Certificate
}

func isSTSRole(el *etree.Element) bool {
	if !isEl(el, NSMD, "RoleDescriptor") {
		return false
	}
	ns, local, ok := xsiType(el)
	return ok && ns == NSFed && local == "SecurityTokenServiceType"
}

func certificatesOf(role *etree.Element, use string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, descriptor := range children(role, NSMD, "KeyDescriptor") {
		declared, has := attr(descriptor, "use")
		if has && declared != "" && declared != use {
			continue
		}
		for _, data := range descendants(descriptor, NSDS, "X509Data") {
			first := children(data, NSDS, "X509Certificate")
			if len(first) == 0 {
				continue
			}
			cert, err := loadCert(toPEM(textOf(first[0])))
			if err != nil {
				return nil, failCause("metadata", "a "+use+" certificate in the identity provider's metadata cannot be read", err)
			}
			out = append(out, cert)
		}
	}
	return out, nil
}

func fedAddresses(role *etree.Element, local string) []string {
	var out []string
	for _, endpoint := range children(role, NSFed, local) {
		out = append(out, wsaAddresses(endpoint)...)
	}
	return out
}

func hasSTS(element *etree.Element) bool {
	for _, role := range children(element, NSMD, "RoleDescriptor") {
		if isSTSRole(role) {
			return true
		}
	}
	return false
}

// ReadIdPMetadata reads an EntityDescriptor or an EntitiesDescriptor.
func ReadIdPMetadata(xml string, entityID string) (*IdPMetadata, error) {
	_, root, err := parseXML(xml, "the identity provider metadata")
	if err != nil {
		return nil, err
	}
	var entity *etree.Element
	if isEl(root, NSMD, "EntityDescriptor") {
		entity = root
	} else if isEl(root, NSMD, "EntitiesDescriptor") {
		var all []*etree.Element
		for _, item := range descendants(root, NSMD, "EntityDescriptor") {
			if hasSTS(item) {
				all = append(all, item)
			}
		}
		if entityID != "" {
			for _, item := range all {
				if id, _ := attr(item, "entityID"); id == entityID {
					entity = item
					break
				}
			}
		} else if len(all) == 1 {
			entity = all[0]
		}
		if entity == nil {
			if entityID != "" {
				return nil, fail("metadata", "the metadata aggregate has no WS-Federation identity provider "+entityID)
			}
			return nil, fmtErr("metadata", "the metadata aggregate holds %d WS-Federation identity providers; name one with idpEntityId", len(all))
		}
	} else {
		return nil, fail("metadata", "the identity provider metadata is not an EntityDescriptor")
	}
	identifier, _ := attr(entity, "entityID")
	if identifier == "" {
		return nil, fail("metadata", "the identity provider metadata has no entityID")
	}
	if entityID != "" && identifier != entityID {
		return nil, fail("metadata", "the metadata describes "+identifier+", not "+entityID)
	}
	var role *etree.Element
	for _, item := range children(entity, NSMD, "RoleDescriptor") {
		if isSTSRole(item) {
			role = item
			break
		}
	}
	if role == nil {
		return nil, fail("metadata", identifier+"'s metadata has no fed:SecurityTokenServiceType RoleDescriptor, so it is not a WS-Federation identity provider")
	}
	passive := fedAddresses(role, "PassiveRequestorEndpoint")
	if len(passive) == 0 {
		return nil, fail("metadata", identifier+"'s metadata names no PassiveRequestorEndpoint")
	}
	endpoint := passive[0]
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, fail("metadata", identifier+"'s PassiveRequestorEndpoint "+endpoint+" is not an http(s) URL")
	}
	var offered []string
	for _, types := range children(role, NSFed, "TokenTypesOffered") {
		for _, token := range children(types, NSFed, "TokenType") {
			uri, _ := attr(token, "Uri")
			if uri != "" {
				offered = append(offered, uri)
			}
		}
	}
	if len(offered) > 0 {
		ok := false
		for _, token := range offered {
			if isSaml2Token(token) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fail("metadata", identifier+" offers no SAML 2.0 token (it offers "+strings.Join(offered, ", ")+")")
		}
	}
	signing, err := certificatesOf(role, "signing")
	if err != nil {
		return nil, err
	}
	if len(signing) == 0 {
		idp := children(entity, NSMD, "IDPSSODescriptor")
		if len(idp) > 0 {
			signing, err = certificatesOf(idp[0], "signing")
			if err != nil {
				return nil, err
			}
		}
	}
	if len(signing) == 0 {
		return nil, fail("metadata", identifier+"'s metadata names no signing certificate")
	}
	return &IdPMetadata{EntityID: identifier, PassiveRequestorEndpoint: endpoint, TokenTypesOffered: offered, SigningCertificates: signing}, nil
}

func certPEMBody(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return pemBody(string(block))
}

// WriteRPMetadata writes an ApplicationServiceType entity descriptor.
func WriteRPMetadata(realm, replyURL string, certificate *x509.Certificate) string {
	key := ""
	if certificate != nil {
		var methods strings.Builder
		for _, method := range encryptionMethods {
			methods.WriteString("\n      <md:EncryptionMethod Algorithm=\"" + method + "\"/>")
		}
		key = "    <md:KeyDescriptor use=\"encryption\">\n" +
			"      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + certPEMBody(certificate) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
			methods.String() + "\n" +
			"    </md:KeyDescriptor>\n"
	}
	endpoint := func(local, address string) string {
		return "    <fed:" + local + "><wsa:EndpointReference><wsa:Address>" + escapeXML(address) + "</wsa:Address></wsa:EndpointReference></fed:" + local + ">"
	}
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<md:EntityDescriptor xmlns:md=\"" + NSMD + "\" xmlns:ds=\"" + NSDS + "\" xmlns:fed=\"" + NSFed + "\" " +
		"xmlns:wsa=\"" + NSWSA + "\" xmlns:xsi=\"" + NSXSI + "\" entityID=\"" + escapeXML(realm) + "\">\n" +
		"  <md:RoleDescriptor xsi:type=\"fed:ApplicationServiceType\" protocolSupportEnumeration=\"" + NSFed + "\">\n" +
		key + "    <fed:TokenTypesOffered><fed:TokenType Uri=\"" + SAML2Token + "\"/></fed:TokenTypesOffered>\n" +
		"    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>" + escapeXML(realm) + "</wsa:Address></wsa:EndpointReference></fed:TargetScopes>\n" +
		endpoint("ApplicationServiceEndpoint", replyURL) + "\n" +
		endpoint("SingleSignOutNotificationEndpoint", replyURL) + "\n" +
		endpoint("PassiveRequestorEndpoint", replyURL) + "\n" +
		"  </md:RoleDescriptor>\n" +
		"</md:EntityDescriptor>\n"
}
