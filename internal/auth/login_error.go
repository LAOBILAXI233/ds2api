package auth

import "strconv"

// Login refusals, classified.
//
// ds-free-api's login routine draws a line no retry should cross: a refusal that
// is about the account itself (wrong password, muted, banned, a device the risk
// layer no longer trusts) returns the same answer however often it is asked, and
// retrying it is exactly the traffic that makes upstream escalate. Only the
// other kind of failure (network, 5xx, a WAF hiccup, an unknown code) is worth
// another attempt, and even that one is bounded.
//
// The business codes below are the ones ds-free-api treats as terminal:
//
//	2  credentials are wrong
//	5  the account is muted / limited
//	10 the account is banned
//	11 the device check was refused (risk_device_detected)
const (
	LoginCodeCredentials = 2
	LoginCodeMuted       = 5
	LoginCodeBanned      = 10
	LoginCodeDevice      = 11
)

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
	case LoginCodeCredentials, LoginCodeMuted, LoginCodeBanned, LoginCodeDevice:
		return true
	default:
		return false
	}
}

// IsTerminalLoginError asks whether an error (of any type) is a refusal that
// must not be retried.
func IsTerminalLoginError(err error) bool {
	loginErr, ok := err.(*LoginError)
	return ok && loginErr.Terminal
}

// AsLoginError unwraps a classification, if the error carries one.
func AsLoginError(err error) (*LoginError, bool) {
	loginErr, ok := err.(*LoginError)
	return loginErr, ok
}
