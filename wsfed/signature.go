// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"strings"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
)

const (
	excC14N         = "http://www.w3.org/2001/10/xml-exc-c14n#"
	excC14NComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	c14n10          = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	c14n10Comments  = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	enveloped       = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

var signatureAlgs = map[string]crypto.Hash{
	RSASHA256: crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": crypto.SHA512,
}

var digestAlgs = map[string]crypto.Hash{
	"http://www.w3.org/2001/04/xmlenc#sha256":       crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmlenc#sha512":       crypto.SHA512,
}

func hashAllowed(set map[string]crypto.Hash, alg string) bool {
	_, ok := set[alg]
	return ok
}

func isTransform(alg string) bool {
	switch alg {
	case enveloped, excC14N, excC14NComments, c14n10, c14n10Comments:
		return true
	default:
		return false
	}
}

func isC14N(alg string) bool {
	switch alg {
	case excC14N, excC14NComments, c14n10, c14n10Comments:
		return true
	default:
		return false
	}
}

func isXMLNS(a etree.Attr) bool {
	return a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns")
}

func nsKey(a etree.Attr) string {
	if a.Space == "" && a.Key == "xmlns" {
		return "xmlns"
	}
	return a.Space + ":" + a.Key
}

// hoistNS copies in-scope ancestor namespace declarations onto dst so exclusive
// c14n, which only reads declarations on the element it is given, still sees them.
func hoistNS(src, dst *etree.Element) {
	seen := map[string]bool{}
	for _, a := range dst.Attr {
		if isXMLNS(a) {
			seen[nsKey(a)] = true
		}
	}
	for p := src.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			if !isXMLNS(a) {
				continue
			}
			key := nsKey(a)
			if seen[key] {
				continue
			}
			dst.Attr = append(dst.Attr, a)
			seen[key] = true
		}
	}
}

func canonicalize(el *etree.Element, algorithm, prefixList string) ([]byte, error) {
	dup := el.Copy()
	hoistNS(el, dup)
	var canon dsig.Canonicalizer
	switch algorithm {
	case excC14N:
		canon = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList)
	case excC14NComments:
		canon = dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList)
	case c14n10:
		canon = dsig.MakeC14N10RecCanonicalizer()
	case c14n10Comments:
		canon = dsig.MakeC14N10WithCommentsCanonicalizer()
	default:
		return nil, fail("signature", "canonicalization "+algorithm+" is refused")
	}
	out, err := canon.Canonicalize(dup)
	if err != nil {
		return nil, failCause("signature", "canonicalization failed: "+err.Error(), err)
	}
	return out, nil
}

func digestBytes(h crypto.Hash, data []byte) ([]byte, error) {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:], nil
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:], nil
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:], nil
	default:
		return nil, fail("signature", "unsupported digest")
	}
}

func algorithmOf(parent *etree.Element, local string) string {
	el, err := child(parent, NSDS, local)
	if err != nil || el == nil {
		return ""
	}
	value, _ := attr(el, "Algorithm")
	return value
}

func prefixesOf(method *etree.Element) string {
	if method == nil {
		return ""
	}
	for _, c := range method.ChildElements() {
		if c.Tag == "InclusiveNamespaces" {
			value, ok := attr(c, "PrefixList")
			if !ok {
				return ""
			}
			return value
		}
	}
	return ""
}

func b64El(el *etree.Element) ([]byte, error) {
	raw := ""
	if el != nil {
		raw = strings.Join(strings.Fields(textContent(el)), "")
	}
	if raw == "" {
		return []byte{}, nil
	}
	out, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		out, err = base64.RawStdEncoding.DecodeString(raw)
	}
	return out, err
}

func removeEnveloped(el *etree.Element) {
	for _, c := range el.ChildElements() {
		if isEl(c, NSDS, "Signature") {
			el.RemoveChild(c)
			return
		}
	}
}

func referenceC14N(element, signature *etree.Element, transforms []*etree.Element) ([]byte, string, error) {
	algorithm := excC14N
	prefixes := ""
	envelopedSeen := false
	for _, transform := range transforms {
		alg, _ := attr(transform, "Algorithm")
		if alg == enveloped {
			envelopedSeen = true
			continue
		}
		if isC14N(alg) {
			algorithm = alg
			prefixes = prefixesOf(transform)
		}
	}
	dup := element.Copy()
	hoistNS(element, dup)
	if envelopedSeen || signature != nil {
		removeEnveloped(dup)
	}
	var canon dsig.Canonicalizer
	switch algorithm {
	case excC14N:
		canon = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixes)
	case excC14NComments:
		canon = dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixes)
	case c14n10:
		canon = dsig.MakeC14N10RecCanonicalizer()
	case c14n10Comments:
		canon = dsig.MakeC14N10WithCommentsCanonicalizer()
	default:
		return nil, algorithm, fail("signature", "canonicalization "+algorithm+" is refused")
	}
	out, err := canon.Canonicalize(dup)
	if err != nil {
		return nil, algorithm, failCause("signature", "canonicalization failed: "+err.Error(), err)
	}
	return out, algorithm, nil
}

// verifySigned checks the enveloped signature on el. The returned string is the canonical XML that was signed.
func verifySigned(el *etree.Element, certs []*x509.Certificate, what string) (string, error) {
	sigEl, err := child(el, NSDS, "Signature")
	if err != nil {
		return "", err
	}
	if sigEl == nil {
		return "", nil
	}
	elementID, ok := attr(el, "ID")
	if !ok || elementID == "" {
		return "", fail("signature", what+" is signed but has no ID for the signature to refer to")
	}
	signedInfo, err := child(sigEl, NSDS, "SignedInfo")
	if err != nil {
		return "", err
	}
	if signedInfo == nil {
		return "", fail("signature", what+"'s signature has no SignedInfo")
	}
	c14nAlg := algorithmOf(signedInfo, "CanonicalizationMethod")
	if !isC14N(c14nAlg) {
		shown := c14nAlg
		if shown == "" {
			shown = "(none)"
		}
		return "", fail("signature", what+"'s signature uses the canonicalization "+shown+", which is refused")
	}
	sigAlg := algorithmOf(signedInfo, "SignatureMethod")
	hashID, ok := signatureAlgs[sigAlg]
	if !ok {
		shown := sigAlg
		if shown == "" {
			shown = "(none)"
		}
		return "", fail("signature", what+"'s signature uses "+shown+", which is refused (SHA-1 and non-RSA algorithms are not accepted)")
	}
	refs := children(signedInfo, NSDS, "Reference")
	if len(refs) != 1 {
		return "", fmtErr("signature", "%s's signature has %d references; exactly one is accepted", what, len(refs))
	}
	ref := refs[0]
	uri, _ := attr(ref, "URI")
	if uri != "#"+elementID {
		shown := uri
		if shown == "" {
			shown = "(nothing)"
		}
		return "", fail("signature", what+"'s signature refers to "+shown+", not to "+what+" itself (#"+elementID+")")
	}
	digestAlg := algorithmOf(ref, "DigestMethod")
	digestHash, ok := digestAlgs[digestAlg]
	if !ok {
		shown := digestAlg
		if shown == "" {
			shown = "(none)"
		}
		return "", fail("signature", what+"'s signature digests with "+shown+", which is refused")
	}
	transformsEl, err := child(ref, NSDS, "Transforms")
	if err != nil {
		return "", err
	}
	var transformEls []*etree.Element
	if transformsEl != nil {
		transformEls = children(transformsEl, NSDS, "Transform")
	}
	for _, transform := range transformEls {
		alg, _ := attr(transform, "Algorithm")
		if !isTransform(alg) {
			shown := alg
			if shown == "" {
				shown = "(none)"
			}
			return "", fail("signature", what+"'s signature uses the transform "+shown+", which is refused")
		}
	}
	if len(certs) == 0 {
		return "", fail("signature", "no signing certificate is known for the identity provider, so "+what+" cannot be verified")
	}
	refC14N, _, err := referenceC14N(el, sigEl, transformEls)
	if err != nil {
		return "", err
	}
	got, err := digestBytes(digestHash, refC14N)
	if err != nil {
		return "", err
	}
	digestValue, err := child(ref, NSDS, "DigestValue")
	if err != nil {
		return "", err
	}
	want, decErr := b64El(digestValue)
	if decErr != nil || !bytesEqual(got, want) {
		return "", fail("signature", what+"'s signature does not verify against the identity provider's certificate: the signature does not verify")
	}
	infoBytes, err := canonicalize(signedInfo, c14nAlg, prefixesOf(mustChild(signedInfo, "CanonicalizationMethod")))
	if err != nil {
		return "", err
	}
	sigBytes, decErr := b64El(mustChildEl(sigEl))
	if decErr != nil {
		return "", fail("signature", what+"'s signature does not verify against the identity provider's certificate: "+decErr.Error())
	}
	hashed, err := digestBytes(hashID, infoBytes)
	if err != nil {
		return "", err
	}
	reason := "the signature does not verify"
	for _, cert := range certs {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			reason = "the certificate key is not RSA"
			continue
		}
		if err := rsa.VerifyPKCS1v15(pub, hashID, hashed, sigBytes); err != nil {
			reason = err.Error()
			continue
		}
		return string(refC14N), nil
	}
	return "", fail("signature", what+"'s signature does not verify against the identity provider's certificate: "+reason)
}

func mustChild(parent *etree.Element, local string) *etree.Element {
	el, _ := child(parent, NSDS, local)
	return el
}

func mustChildEl(sig *etree.Element) *etree.Element {
	el, _ := child(sig, NSDS, "SignatureValue")
	return el
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SignEnveloped signs elementID inside xml with exclusive c14n and RSA-SHA256.
// The stub identity provider and the verifier share this canonicalization.
func SignEnveloped(xml, elementID string, key *rsa.PrivateKey, certPEM string) (string, error) {
	doc, root, err := parseXML(xml, "the signed element")
	if err != nil {
		return "", err
	}
	target := findID(root, elementID)
	if target == nil {
		return "", fail("signature", "no element ID "+elementID)
	}
	refC14N, err := canonicalize(target, excC14N, "")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(refC14N)
	digest := base64.StdEncoding.EncodeToString(sum[:])
	sig := signatureElement(elementID, certPEM, digest)
	issuer, err := child(target, NSSaml, "Issuer")
	if err != nil {
		return "", err
	}
	insertAfter(target, issuer, sig)
	signedInfo, err := child(sig, NSDS, "SignedInfo")
	if err != nil || signedInfo == nil {
		return "", fail("signature", "SignedInfo was not built")
	}
	info, err := canonicalize(signedInfo, excC14N, "")
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256(info)
	raw, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", failCause("signature", "the signature could not be produced", err)
	}
	value, _ := child(sig, NSDS, "SignatureValue")
	value.SetText(base64.StdEncoding.EncodeToString(raw))
	return writeDoc(doc)
}

func insertAfter(parent, after, child *etree.Element) {
	if parent == nil || child == nil {
		return
	}
	if after == nil {
		parent.AddChild(child)
		return
	}
	for i, tok := range parent.Child {
		el, ok := tok.(*etree.Element)
		if ok && el == after {
			parent.InsertChildAt(i+1, child)
			return
		}
	}
	parent.AddChild(child)
}

func signatureElement(elementID, certPEM, digest string) *etree.Element {
	sig := etree.NewElement("Signature")
	sig.Space = "ds"
	sig.CreateAttr("xmlns:ds", NSDS)
	info := sig.CreateElement("SignedInfo")
	info.Space = "ds"
	c14n := info.CreateElement("CanonicalizationMethod")
	c14n.Space = "ds"
	c14n.CreateAttr("Algorithm", excC14N)
	method := info.CreateElement("SignatureMethod")
	method.Space = "ds"
	method.CreateAttr("Algorithm", RSASHA256)
	ref := info.CreateElement("Reference")
	ref.Space = "ds"
	ref.CreateAttr("URI", "#"+elementID)
	transforms := ref.CreateElement("Transforms")
	transforms.Space = "ds"
	t1 := transforms.CreateElement("Transform")
	t1.Space = "ds"
	t1.CreateAttr("Algorithm", enveloped)
	t2 := transforms.CreateElement("Transform")
	t2.Space = "ds"
	t2.CreateAttr("Algorithm", excC14N)
	dm := ref.CreateElement("DigestMethod")
	dm.Space = "ds"
	dm.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	dv := ref.CreateElement("DigestValue")
	dv.Space = "ds"
	dv.SetText(digest)
	ki := sig.CreateElement("KeyInfo")
	ki.Space = "ds"
	data := ki.CreateElement("X509Data")
	data.Space = "ds"
	encoded := data.CreateElement("X509Certificate")
	encoded.Space = "ds"
	encoded.SetText(pemBody(certPEM))
	sv := sig.CreateElement("SignatureValue")
	sv.Space = "ds"
	return sig
}
