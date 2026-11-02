// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import "fmt"

// WsFedError is a config, metadata, message, xml, signature, validation, replay, decryption, or ssf failure.
type WsFedError struct {
	Code    string
	Message string
	Cause   error
}

func (e *WsFedError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *WsFedError) Unwrap() error { return e.Cause }

func fail(code, message string) *WsFedError {
	return &WsFedError{Code: code, Message: message}
}

func failCause(code, message string, cause error) *WsFedError {
	return &WsFedError{Code: code, Message: message, Cause: cause}
}

func asWs(err error) *WsFedError {
	if err == nil {
		return nil
	}
	if w, ok := err.(*WsFedError); ok {
		return w
	}
	return nil
}

func fmtErr(code, format string, args ...any) *WsFedError {
	return fail(code, fmt.Sprintf(format, args...))
}

// String returns a pointer for optional fields such as LoginOptions.RelayState.
func String(s string) *string { return &s }
