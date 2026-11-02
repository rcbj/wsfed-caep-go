// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxRelayState = 1024

var protocolParams = map[string]bool{
	"wa": true, "wtrealm": true, "wreply": true, "wctx": true, "wct": true,
	"wreq": true, "wreqptr": true, "wfresh": true, "wauth": true, "whr": true,
}

// LoginRequest is a passive sign-in redirect.
type LoginRequest struct {
	ID   string
	URL  string
	Wctx string
}

// ReplyRequest is the browser's POST (or GET) to the reply URL.
// Body is a raw form string or a map[string]string.
type ReplyRequest struct {
	Method string
	URL    string
	Body   any
}

// LoginOptions are the optional parts of a sign-in. A nil RelayState omits ru.
type LoginOptions struct {
	RelayState           *string
	ForceAuthn           bool
	Freshness            *int
	AuthenticationMethod string
	HomeRealm            string
	Params               map[string]string
}

// RelyingParty is a WS-Federation 1.2 passive requestor.
type RelyingParty struct {
	Config *Resolved
	Idp    *IdPMetadata
	replay *MemoryReplayCache
}

// Create resolves config and reads the identity provider's metadata.
func Create(config map[string]any, baseDir string) (*RelyingParty, error) {
	resolved, err := ResolveConfig(config, baseDir)
	if err != nil {
		return nil, err
	}
	party := &RelyingParty{Config: resolved, replay: NewMemoryReplayCache(0)}
	if _, err := party.RefreshMetadata(); err != nil {
		return nil, err
	}
	return party, nil
}

// FromFile loads wsfed.json. Nil override values are ignored.
func FromFile(path string, overrides map[string]any) (*RelyingParty, error) {
	resolved, err := ReadConfigFile(path, overrides)
	if err != nil {
		return nil, err
	}
	party := &RelyingParty{Config: resolved, replay: NewMemoryReplayCache(0)}
	if _, err := party.RefreshMetadata(); err != nil {
		return nil, err
	}
	return party, nil
}

// RefreshMetadata reads idpMetadata again.
func (rp *RelyingParty) RefreshMetadata() (*IdPMetadata, error) {
	source := rp.Config.IdPMetadata
	var xml string
	switch {
	case strings.HasPrefix(source, "<"):
		xml = source
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		var tlsIn *tlsMaterial
		if rp.Config.IdPCA != "" {
			tlsIn = &tlsMaterial{CA: rp.Config.IdPCA}
		}
		answer, err := send(source, "GET", map[string]string{"accept": "application/samlmetadata+xml, application/xml, text/xml"}, nil, tlsIn, "metadata")
		if err != nil {
			return nil, err
		}
		if answer.Status != 200 {
			return nil, fail("metadata", source+" answered HTTP "+itoa(answer.Status))
		}
		xml = answer.Body
	default:
		raw, err := os.ReadFile(source)
		if err != nil {
			return nil, failCause("metadata", "the identity provider metadata file "+source+" cannot be read", err)
		}
		xml = string(raw)
	}
	meta, err := ReadIdPMetadata(xml, rp.Config.IdPEntityID)
	if err != nil {
		return nil, err
	}
	rp.Idp = meta
	return meta, nil
}

func (rp *RelyingParty) idp() (*IdPMetadata, error) {
	if rp.Idp == nil {
		return nil, fail("metadata", "the identity provider's metadata has not been loaded")
	}
	return rp.Idp, nil
}

// Metadata is this relying party's federation metadata.
func (rp *RelyingParty) Metadata() string {
	return WriteRPMetadata(rp.Config.Realm, rp.Config.ReplyURL, rp.Config.Certificate)
}

func newID() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func joinQuery(endpoint, query string) string {
	joiner := "?"
	if strings.Contains(endpoint, "?") {
		joiner = "&"
	}
	return endpoint + joiner + query
}

// Login starts a WS-Federation sign-in. Sign-in does not send OAuth scopes.
func (rp *RelyingParty) Login(opts *LoginOptions) (*LoginRequest, error) {
	if opts == nil {
		opts = &LoginOptions{}
	}
	idp, err := rp.idp()
	if err != nil {
		return nil, err
	}
	if opts.RelayState != nil && len([]byte(*opts.RelayState)) > maxRelayState {
		return nil, fail("config", "relayState is longer than "+itoa(maxRelayState)+" bytes")
	}
	requestID, err := newID()
	if err != nil {
		return nil, failCause("config", "a request id could not be chosen", err)
	}
	wctxValues := url.Values{}
	wctxValues.Set("id", requestID)
	wctx := "id=" + url.QueryEscape(requestID)
	if opts.RelayState != nil {
		wctx += "&ru=" + url.QueryEscape(*opts.RelayState)
		wctxValues.Set("ru", *opts.RelayState)
	}
	_ = wctxValues
	pairs := url.Values{}
	order := []string{"wa", "wtrealm", "wreply", "wctx", "wct"}
	pairs.Set("wa", "wsignin1.0")
	pairs.Set("wtrealm", rp.Config.Realm)
	pairs.Set("wreply", rp.Config.ReplyURL)
	pairs.Set("wctx", wctx)
	pairs.Set("wct", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	if rp.Config.RequestTokenType {
		order = append(order, "wreq")
		pairs.Set("wreq", `<wst:RequestSecurityToken xmlns:wst="`+NSTrust13+`"><wst:TokenType>`+SAML2Token+`</wst:TokenType></wst:RequestSecurityToken>`)
	}
	if opts.ForceAuthn {
		order = append(order, "wfresh")
		pairs.Set("wfresh", "0")
	} else if opts.Freshness != nil {
		if *opts.Freshness < 0 {
			return nil, fail("config", "freshness is a whole number of minutes")
		}
		order = append(order, "wfresh")
		pairs.Set("wfresh", itoa(*opts.Freshness))
	}
	if opts.AuthenticationMethod != "" {
		order = append(order, "wauth")
		pairs.Set("wauth", opts.AuthenticationMethod)
	}
	if opts.HomeRealm != "" {
		order = append(order, "whr")
		pairs.Set("whr", opts.HomeRealm)
	}
	for key, value := range opts.Params {
		if protocolParams[key] {
			return nil, fail("config", "params cannot set "+key+"; it is the protocol's own")
		}
		order = append(order, key)
		pairs.Set(key, value)
	}
	return &LoginRequest{ID: requestID, URL: joinQuery(idp.PassiveRequestorEndpoint, encodeOrder(pairs, order)), Wctx: wctx}, nil
}

func encodeOrder(values url.Values, order []string) string {
	var b strings.Builder
	first := true
	seen := map[string]bool{}
	for _, key := range order {
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, value := range values[key] {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(url.QueryEscape(key))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(value))
		}
	}
	return b.String()
}

// HandleReply accepts a SAML 2.0 assertion posted to the reply URL.
// requestIDs are the sign-ins this browser still has outstanding. None means unsolicited.
func (rp *RelyingParty) HandleReply(request ReplyRequest, requestIDs []string) (*Login, error) {
	idp, err := rp.idp()
	if err != nil {
		return nil, err
	}
	form, query := paramsOf(request)
	wa := ""
	if value, ok := form["wa"]; ok {
		wa = value
	} else {
		wa = query["wa"]
	}
	if wa == "wsignoutcleanup1.0" || wa == "wsignout1.0" {
		return nil, fail("message", "the request is "+wa+", a sign-out, not a sign-in response; see isSignOutCleanup()")
	}
	if strings.ToUpper(request.Method) != "POST" {
		return nil, fail("message", "a sign-in response is POSTed (WS-Federation 13.2.2); this request is a GET")
	}
	if wa != "wsignin1.0" {
		shown := wa
		if shown == "" {
			shown = "(none)"
		}
		return nil, fail("message", "the request's wa is "+shown+", not wsignin1.0")
	}
	if _, ok := form["wresultptr"]; ok {
		return nil, fail("message", "the response is by reference (wresultptr), which is never dereferenced; only wresult is accepted")
	}
	wresult := form["wresult"]
	if wresult == "" {
		return nil, fail("message", "the request carries no wresult")
	}
	wctx := firstMap(form["wctx"])
	gotID, hasID := wctx["id"]
	if hasID {
		ok := false
		for _, id := range requestIDs {
			if id == gotID {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fail("validation", "the response answers "+gotID+", which is not a sign-in this browser has outstanding")
		}
	} else if !rp.Config.AllowUnsolicited {
		return nil, fail("validation", "the response is unsolicited (its wctx names no request), and unsolicited responses are not accepted")
	}
	token, err := ValidateToken(wresult, tokenContext{
		Realm:                   rp.Config.Realm,
		ReplyURL:                rp.Config.ReplyURL,
		IdPEntityID:             idp.EntityID,
		IdPCertificates:         idp.SigningCertificates,
		DecryptionKey:           rp.Config.PrivateKey,
		ClockSkewMs:             rp.Config.ClockSkewMs,
		WantAssertionsEncrypted: rp.Config.WantAssertionsEncrypted,
		Replay:                  rp.replay,
	})
	if err != nil {
		return nil, err
	}
	if hasID {
		id := gotID
		token.RequestID = &id
	}
	if ru, ok := wctx["ru"]; ok {
		value := ru
		token.RelayState = &value
	}
	return token, nil
}

// IsSignOutCleanup reports wa=wsignoutcleanup1.0 or wa=wsignout1.0.
func (rp *RelyingParty) IsSignOutCleanup(request ReplyRequest) bool {
	form, query := paramsOf(request)
	wa := ""
	if value, ok := form["wa"]; ok {
		wa = value
	} else {
		wa = query["wa"]
	}
	return wa == "wsignoutcleanup1.0" || wa == "wsignout1.0"
}

// Logout is a wsignout1.0 redirect. An empty reply omits wreply.
func (rp *RelyingParty) Logout(reply string) (string, error) {
	idp, err := rp.idp()
	if err != nil {
		return "", err
	}
	pairs := url.Values{}
	order := []string{"wa", "wtrealm"}
	pairs.Set("wa", "wsignout1.0")
	pairs.Set("wtrealm", rp.Config.Realm)
	if reply != "" {
		order = append(order, "wreply")
		pairs.Set("wreply", reply)
	}
	return joinQuery(idp.PassiveRequestorEndpoint, encodeOrder(pairs, order)), nil
}

func firstMap(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		for _, part := range strings.Split(raw, "&") {
			if part == "" {
				continue
			}
			key, value, _ := strings.Cut(part, "=")
			key, _ = url.QueryUnescape(key)
			value, _ = url.QueryUnescape(value)
			if _, ok := out[key]; !ok {
				out[key] = value
			}
		}
		return out
	}
	for key, list := range values {
		if len(list) > 0 {
			if _, ok := out[key]; !ok {
				out[key] = list[0]
			}
		}
	}
	return out
}

func formOf(body any) map[string]string {
	switch value := body.(type) {
	case nil:
		return map[string]string{}
	case string:
		return firstMap(value)
	case map[string]string:
		out := map[string]string{}
		for key, item := range value {
			out[key] = item
		}
		return out
	case map[string]any:
		out := map[string]string{}
		for key, item := range value {
			if text, ok := item.(string); ok {
				out[key] = text
			}
		}
		return out
	default:
		return map[string]string{}
	}
}

func paramsOf(request ReplyRequest) (map[string]string, map[string]string) {
	raw := request.URL
	query := ""
	if i := strings.Index(raw, "?"); i >= 0 {
		query = raw[i+1:]
		if j := strings.Index(query, "#"); j >= 0 {
			query = query[:j]
		}
	}
	parsed := firstMap(query)
	form := map[string]string{}
	if strings.ToUpper(request.Method) == "POST" {
		form = formOf(request.Body)
	}
	return form, parsed
}
