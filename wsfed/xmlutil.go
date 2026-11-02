// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"regexp"
	"strings"

	"github.com/beevik/etree"
)

var doctypeRE = regexp.MustCompile(`(?i)<!DOCTYPE|<!ENTITY`)

var idNames = map[string]bool{"ID": true, "Id": true, "id": true}

func parseXML(text, what string) (*etree.Document, *etree.Element, error) {
	if doctypeRE.MatchString(text) {
		return nil, nil, fail("xml", what+" carries a DOCTYPE or an entity declaration, which WS-Federation never needs")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(text); err != nil {
		return nil, nil, failCause("xml", what+" is not well-formed XML: "+err.Error(), err)
	}
	root := doc.Root()
	if root == nil {
		return nil, nil, fail("xml", what+" is not well-formed XML: no document element")
	}
	return doc, root, nil
}

func lookupPrefix(el *etree.Element, prefix string) (string, bool) {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, a := range cur.Attr {
			if prefix == "" && a.Space == "" && a.Key == "xmlns" {
				return a.Value, true
			}
			if prefix != "" && a.Space == "xmlns" && a.Key == prefix {
				return a.Value, true
			}
		}
	}
	return "", false
}

func elementNS(el *etree.Element) string {
	if el == nil {
		return ""
	}
	if strings.Contains(el.Space, "://") || strings.HasPrefix(el.Space, "urn:") {
		return el.Space
	}
	if uri, ok := lookupPrefix(el, el.Space); ok {
		return uri
	}
	return ""
}

func isEl(el *etree.Element, ns, local string) bool {
	return el != nil && el.Tag == local && elementNS(el) == ns
}

func children(el *etree.Element, ns, local string) []*etree.Element {
	if el == nil {
		return nil
	}
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == local && elementNS(c) == ns {
			out = append(out, c)
		}
	}
	return out
}

func child(el *etree.Element, ns, local string) (*etree.Element, error) {
	found := children(el, ns, local)
	if len(found) > 1 {
		return nil, fail("validation", "<"+el.Tag+"> has more than one <"+local+">")
	}
	if len(found) == 0 {
		return nil, nil
	}
	return found[0], nil
}

func descendants(el *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element
	if el == nil {
		return out
	}
	var walk func(*etree.Element)
	walk = func(cur *etree.Element) {
		for _, c := range cur.ChildElements() {
			if c.Tag == local && elementNS(c) == ns {
				out = append(out, c)
			}
			walk(c)
		}
	}
	walk(el)
	return out
}

func elementChildren(el *etree.Element) []*etree.Element {
	if el == nil {
		return nil
	}
	return el.ChildElements()
}

func textContent(el *etree.Element) string {
	if el == nil {
		return ""
	}
	var b strings.Builder
	var walk func(*etree.Element)
	walk = func(cur *etree.Element) {
		for _, tok := range cur.Child {
			switch n := tok.(type) {
			case *etree.CharData:
				b.WriteString(n.Data)
			case *etree.Element:
				walk(n)
			}
		}
	}
	walk(el)
	if b.Len() == 0 {
		return el.Text()
	}
	return b.String()
}

func textOf(el *etree.Element) string {
	return strings.TrimSpace(textContent(el))
}

func attr(el *etree.Element, name string) (string, bool) {
	if el == nil {
		return "", false
	}
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == name {
			return a.Value, true
		}
	}
	return "", false
}

func attrNS(el *etree.Element, ns, local string) (string, bool) {
	if el == nil {
		return "", false
	}
	for _, a := range el.Attr {
		name := a.Key
		if i := strings.IndexByte(name, ':'); a.Space == "" && i >= 0 {
			name = name[i+1:]
		}
		if name != local {
			continue
		}
		uri, _ := lookupPrefix(el, a.Space)
		if a.Space == ns || uri == ns || (a.Space == "" && ns == "" && !strings.Contains(a.Key, ":")) {
			return a.Value, true
		}
	}
	return "", false
}

func wsaAddresses(el *etree.Element) []string {
	var out []string
	for _, node := range append(descendants(el, NSWSA, "Address"), descendants(el, NSWSA2004, "Address")...) {
		if value := textOf(node); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func assertUniqueIDs(root *etree.Element) error {
	seen := map[string]bool{}
	var walk func(*etree.Element) error
	walk = func(el *etree.Element) error {
		for _, a := range el.Attr {
			local := a.Key
			if a.Space == "" {
				if i := strings.IndexByte(local, ':'); i >= 0 {
					local = local[i+1:]
				}
			}
			if !idNames[local] || a.Value == "" {
				continue
			}
			if seen[a.Value] {
				return fail("signature", "two elements carry the ID "+a.Value)
			}
			seen[a.Value] = true
		}
		for _, c := range el.ChildElements() {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root)
}

func escapeXML(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}

func pemBody(pem string) string {
	pem = strings.ReplaceAll(pem, "-----BEGIN CERTIFICATE-----", "")
	pem = strings.ReplaceAll(pem, "-----END CERTIFICATE-----", "")
	pem = strings.ReplaceAll(pem, " ", "")
	pem = strings.ReplaceAll(pem, "\n", "")
	pem = strings.ReplaceAll(pem, "\r", "")
	pem = strings.ReplaceAll(pem, "\t", "")
	return pem
}

func toPEM(b64 string) string {
	body := strings.Join(strings.Fields(b64), "")
	var lines []string
	for i := 0; i < len(body); i += 64 {
		j := i + 64
		if j > len(body) {
			j = len(body)
		}
		lines = append(lines, body[i:j])
	}
	return "-----BEGIN CERTIFICATE-----\n" + strings.Join(lines, "\n") + "\n-----END CERTIFICATE-----\n"
}

func xsiType(el *etree.Element) (ns, local string, ok bool) {
	value, found := attrNS(el, NSXSI, "type")
	if !found || value == "" {
		return "", "", false
	}
	if i := strings.Index(value, ":"); i >= 0 {
		prefix := strings.TrimSpace(value[:i])
		local = strings.TrimSpace(value[i+1:])
		uri, _ := lookupPrefix(el, prefix)
		return uri, local, true
	}
	uri, _ := lookupPrefix(el, "")
	return uri, strings.TrimSpace(value), true
}

func findID(root *etree.Element, id string) *etree.Element {
	if root == nil {
		return nil
	}
	if v, ok := attr(root, "ID"); ok && v == id {
		return root
	}
	for _, c := range root.ChildElements() {
		if found := findID(c, id); found != nil {
			return found
		}
	}
	return nil
}

func writeDoc(doc *etree.Document) (string, error) {
	doc.WriteSettings = etree.WriteSettings{}
	return doc.WriteToString()
}
