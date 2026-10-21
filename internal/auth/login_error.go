package auth

import (
	"errors"
	"strconv"
)

// Login refusals, classified.
//
// ds-free-api's login routine draws a line no retry should cross: a refusal that
// is about the account itself (wrong password, muted, banned, a device the risk
// layer no longer trusts) returns the same answer however often it is asked, and
// retrying it is exactly the traffic that makes upstream escalate. Only the
// other kind of failure (network, 5xx, a WAF hiccup, an unknown code) is worth
// another attempt, and even that one is bounded.
//
// The business codes below are the ones the web client itself enumerates
// (captured from its own bundle: LOGIN_ERROR_CODE / LOGIN_BY_MOBILE_SMS_ERROR_CODE),
// which is the authority on what a sign-in can answer:
//
//	2  PASSWORD_OR_USER_NAME_IS_WRONG
//	5  the account is muted / limited
//	10 USER_IS_BANNED
//	11 RISK_DEVICE_DETECTED   — the risk layer refused this device
//	12 MOBILE_RESTRICTED      — this number/channel may not sign in here
//	13 SIGNATURE_REQUIRED     — upstream wants a device signature (human step)
//	14 OTP_REQUIRED           — upstream wants a verification code (human step)
//
// 13 and 14 are the codes that separate "wrong password" from "a person has to
// verify this device". A gateway cannot answer either, so retrying is pointless —
// but retiring the account would be wrong too: the account is fine, only the
// device is unverified. They are parked instead, and the operator clears it by
// signing in from a browser and importing that token.
const (
	LoginCodeCredentials      = 2
	LoginCodeMuted            = 5
	LoginCodeBanned           = 10
	LoginCodeDevice           = 11
	LoginCodeMobileRestricted = 12
	LoginCodeSignature        = 13
	LoginCodeOTP              = 14
)

// NeedsHumanVerification reports whether a refusal is the "a person must verify
// this device" kind: answerable only by completing a challenge in a browser.
func NeedsHumanVerification(code int) bool {
	return code == LoginCodeSignature || code == LoginCodeOTP
}

// LoginError is a sign-in that upstream answered with a business code rather
// than a transport failure.
type LoginError struct {
	Code int
	// Message is what upstream said, or this project's own wording when the
	// refusal never reached upstream.
	Message string
	// Terminal marks a refusal that retrying cannot change.
	Terminal bool
}

func (e *LoginError) Error() string {
	if e == nil {
		return "login refused"
	}
	if e.Code == 0 {
		return "login refused: " + e.Message
	}
	return "login refused (" + strconv.Itoa(e.Code) + "): " + e.Message
}

// NewLoginError builds a classified refusal.
func NewLoginError(code int, message string) *LoginError {
	return &LoginError{Code: code, Message: message, Terminal: IsTerminalLoginCode(code)}
}

// IsTerminalLoginCode reports whether a business code is an account-level
// refusal rather than a transient one.
func IsTerminalLoginCode(code int) bool {
	switch code {
	case LoginCodeCredentials, LoginCodeMuted, LoginCodeBanned, LoginCodeDevice,
		LoginCodeMobileRestricted, LoginCodeSignature, LoginCodeOTP:
		return true
	default:
		return false
	}
}

// IsTerminalLoginError asks whether an error (of any type, possibly wrapped) is a
// refusal that must not be retried.
func IsTerminalLoginError(err error) bool {
	loginErr, ok := AsLoginError(err)
	return ok && loginErr.Terminal
}

// AsLoginError unwraps a classification, if the error carries one.
func AsLoginError(err error) (*LoginError, bool) {
	var loginErr *LoginError
	if errors.As(err, &loginErr) {
		return loginErr, true
	}
	return nil, false
}
