// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

const (
	NSSaml                  = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSSaml1                 = "urn:oasis:names:tc:SAML:1.0:assertion"
	NSMD                    = "urn:oasis:names:tc:SAML:2.0:metadata"
	NSDS                    = "http://www.w3.org/2000/09/xmldsig#"
	NSXenc                  = "http://www.w3.org/2001/04/xmlenc#"
	NSXenc11                = "http://www.w3.org/2009/xmlenc11#"
	NSXSI                   = "http://www.w3.org/2001/XMLSchema-instance"
	NSFed                   = "http://docs.oasis-open.org/wsfed/federation/200706"
	NSTrust2005             = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	NSTrust13               = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	NSWSA                   = "http://www.w3.org/2005/08/addressing"
	NSWSA2004               = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	NSWSP                   = "http://schemas.xmlsoap.org/ws/2004/09/policy"
	NSWSP15                 = "http://www.w3.org/ns/ws-policy"
	NSWSU                   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	SAML2Token              = "urn:oasis:names:tc:SAML:2.0:assertion"
	SAML2TokenWSS           = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
	CMBearer                = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	StatusSuccess           = "urn:oasis:names:tc:SAML:2.0:status:Success"
	RSASHA256               = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	DefaultSubjectAttribute = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
)

func isSaml2Token(value string) bool {
	return value == SAML2Token || value == SAML2TokenWSS
}
