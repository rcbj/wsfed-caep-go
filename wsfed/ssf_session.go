// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"strings"
	"sync"
	"time"
)

var mailAttributes = []string{
	"urn:oid:0.9.2342.19200300.100.1.3",
	"mail",
	"email",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
}

// Session is one local sign-in the receiver can end.
type Session struct {
	LocalID    string
	Person     string
	Email      string
	IdPSession string
	ExpiresAt  *time.Time
}

// MemorySessionIndex maps people and identity-provider sessions to local ids.
type MemorySessionIndex struct {
	mu       sync.Mutex
	sessions map[string]Session
	max      int
}

func NewMemorySessionIndex(maxEntries int) *MemorySessionIndex {
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	return &MemorySessionIndex{sessions: map[string]Session{}, max: maxEntries}
}

func (s *MemorySessionIndex) Add(session Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.max {
		if _, ok := s.sessions[session.LocalID]; !ok {
			now := time.Now().UTC()
			for key, value := range s.sessions {
				if value.ExpiresAt != nil && !value.ExpiresAt.After(now) {
					delete(s.sessions, key)
				}
			}
			for len(s.sessions) >= s.max {
				for key := range s.sessions {
					delete(s.sessions, key)
					break
				}
			}
		}
	}
	if session.Email != "" {
		session.Email = strings.ToLower(session.Email)
	}
	s.sessions[session.LocalID] = session
}

func (s *MemorySessionIndex) Remove(localID string) {
	s.mu.Lock()
	delete(s.sessions, localID)
	s.mu.Unlock()
}

func (s *MemorySessionIndex) find(match func(Session) bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	var out []string
	for key, value := range s.sessions {
		if value.ExpiresAt != nil && !value.ExpiresAt.After(now) {
			delete(s.sessions, key)
			continue
		}
		if match(value) {
			out = append(out, key)
		}
	}
	return out
}

func (s *MemorySessionIndex) ByPerson(person string) []string {
	return s.find(func(session Session) bool { return session.Person == person })
}

func (s *MemorySessionIndex) ByEmail(email string) []string {
	wanted := strings.ToLower(email)
	return s.find(func(session Session) bool { return session.Email == wanted })
}

func (s *MemorySessionIndex) ByIdPSession(idpSession string) []string {
	return s.find(func(session Session) bool { return session.IdPSession == idpSession })
}

// TrackedFrom builds the index record for a login.
func TrackedFrom(localID string, login *Login, subjectAttribute string, expiresAt *time.Time) Session {
	if subjectAttribute == "" {
		subjectAttribute = DefaultSubjectAttribute
	}
	person := ""
	if login != nil && login.Attributes != nil {
		if values := login.Attributes[subjectAttribute]; len(values) > 0 {
			person = values[0]
		}
	}
	email := ""
	if login != nil && login.Attributes != nil {
		for _, name := range mailAttributes {
			if values := login.Attributes[name]; len(values) > 0 && values[0] != "" {
				email = values[0]
				break
			}
		}
	}
	if email == "" && login != nil && login.NameIDFormat != nil && *login.NameIDFormat == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" {
		email = login.NameID
	}
	session := Session{LocalID: localID, Person: person, Email: email}
	if login != nil && login.SessionIndex != nil {
		session.IdPSession = *login.SessionIndex
	}
	if expiresAt != nil {
		session.ExpiresAt = expiresAt
	} else if login != nil && login.SessionNotOnOrAfter != nil {
		session.ExpiresAt = login.SessionNotOnOrAfter
	}
	return session
}
