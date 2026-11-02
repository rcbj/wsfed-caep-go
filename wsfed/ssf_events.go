// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

const (
	caepPrefix = "https://schemas.openid.net/secevent/caep/event-type/"
	riscPrefix = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfPrefix  = "https://schemas.openid.net/secevent/ssf/event-type/"
)

// Event maps short names to CAEP, RISC, and SSF event type URIs.
var Event = map[string]string{
	"session_revoked":                    caepPrefix + "session-revoked",
	"token_claims_change":                caepPrefix + "token-claims-change",
	"credential_change":                  caepPrefix + "credential-change",
	"assurance_level_change":             caepPrefix + "assurance-level-change",
	"device_compliance_change":           caepPrefix + "device-compliance-change",
	"session_established":                caepPrefix + "session-established",
	"session_presented":                  caepPrefix + "session-presented",
	"risk_level_change":                  caepPrefix + "risk-level-change",
	"account_credential_change_required": riscPrefix + "account-credential-change-required",
	"account_purged":                     riscPrefix + "account-purged",
	"account_disabled":                   riscPrefix + "account-disabled",
	"account_enabled":                    riscPrefix + "account-enabled",
	"identifier_changed":                 riscPrefix + "identifier-changed",
	"identifier_recycled":                riscPrefix + "identifier-recycled",
	"credential_compromise":              riscPrefix + "credential-compromise",
	"opt_in":                             riscPrefix + "opt-in",
	"opt_out_initiated":                  riscPrefix + "opt-out-initiated",
	"opt_out_cancelled":                  riscPrefix + "opt-out-cancelled",
	"opt_out_effective":                  riscPrefix + "opt-out-effective",
	"recovery_activated":                 riscPrefix + "recovery-activated",
	"recovery_information_changed":       riscPrefix + "recovery-information-changed",
	"sessions_revoked":                   riscPrefix + "sessions-revoked",
	"verification":                       ssfPrefix + "verification",
	"stream_updated":                     ssfPrefix + "stream-updated",
}

// CAEPEvents and RISCEvents are the catalog. Eight CAEP types and fourteen RISC types.
var (
	CAEPEvents []string
	RISCEvents []string
)

func init() {
	for _, value := range Event {
		if len(value) >= len(caepPrefix) && value[:len(caepPrefix)] == caepPrefix {
			CAEPEvents = append(CAEPEvents, value)
		}
		if len(value) >= len(riscPrefix) && value[:len(riscPrefix)] == riscPrefix {
			RISCEvents = append(RISCEvents, value)
		}
	}
}

// DefaultEventsRequested is what a new stream asks to receive.
var DefaultEventsRequested = []string{
	Event["session_revoked"],
	Event["credential_change"],
	Event["assurance_level_change"],
	Event["token_claims_change"],
	Event["account_disabled"],
	Event["account_enabled"],
	Event["account_purged"],
	Event["credential_compromise"],
	Event["sessions_revoked"],
	Event["account_credential_change_required"],
}

// DefaultEndingEvents end local sessions.
var DefaultEndingEvents = []string{
	Event["session_revoked"],
	Event["account_disabled"],
	Event["account_purged"],
	Event["credential_compromise"],
	Event["sessions_revoked"],
}

func simpleSubject(identifier any, issuer string) map[string]string {
	item, ok := identifier.(map[string]any)
	if !ok {
		return map[string]string{}
	}
	fmt := stringOf(item["format"])
	if fmt == "" {
		fmt = stringOf(item["subject_type"])
	}
	out := map[string]string{}
	switch fmt {
	case "iss_sub":
		if sub, ok := item["sub"].(string); ok && (item["iss"] == nil || item["iss"] == issuer) {
			out["sub"] = sub
		}
	case "email":
		if email, ok := item["email"].(string); ok {
			out["email"] = email
		}
	case "opaque":
		if id, ok := item["id"].(string); ok {
			out["opaque"] = id
		}
	case "aliases":
		if list, ok := item["identifiers"].([]any); ok {
			for _, child := range list {
				for key, value := range simpleSubject(child, issuer) {
					out[key] = value
				}
			}
		}
	}
	return out
}

func stringOf(value any) string {
	text, _ := value.(string)
	return text
}

// SubjectOf reads a SET subject into person, email, and idp_session.
func SubjectOf(subID any, issuer string) map[string]string {
	item, ok := subID.(map[string]any)
	if !ok {
		return map[string]string{}
	}
	fmt := stringOf(item["format"])
	if fmt == "" {
		fmt = stringOf(item["subject_type"])
	}
	out := map[string]string{}
	if fmt == "complex" || (fmt == "" && (item["user"] != nil || item["session"] != nil)) {
		user := simpleSubject(item["user"], issuer)
		session := simpleSubject(item["session"], issuer)
		if user["sub"] != "" {
			out["person"] = user["sub"]
		}
		if user["email"] != "" {
			out["email"] = user["email"]
		}
		sessionID := session["opaque"]
		if sessionID == "" {
			sessionID = session["sub"]
		}
		if sessionID != "" {
			out["idp_session"] = sessionID
		}
		return out
	}
	one := simpleSubject(item, issuer)
	if one["sub"] != "" {
		out["person"] = one["sub"]
	}
	if one["email"] != "" {
		out["email"] = one["email"]
	}
	return out
}
