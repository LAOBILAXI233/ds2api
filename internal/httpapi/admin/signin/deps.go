package signin

import (
	"time"

	"ds2api/internal/auth"
	adminshared "ds2api/internal/httpapi/admin/shared"
)

// Handler exposes the sign-in circuit breaker to the admin console.
//
// It holds only `Auth`: the breaker lives in the resolver, and the console needs
// no store access to show (or lift) it.
type Handler struct {
	Auth any
}

var writeJSON = adminshared.WriteJSON

// breaker is the slice of the resolver this handler needs, declared locally so
// the shared deps interfaces and their fakes stay untouched.
type breaker interface {
	RiskStatus() auth.RiskStatus
	ClearRisk()
}

// signinStatusPayload is what the console polls. `supported=false` keeps an
// older resolver (no breaker) from turning the panel into an error toast.
type signinStatusPayload struct {
	Success          bool   `json:"success"`
	Supported        bool   `json:"supported"`
	Active           bool   `json:"active"`
	Strikes          int    `json:"strikes"`
	RemainingSeconds int    `json:"remaining_seconds"`
	Until            string `json:"until,omitempty"`
}

func (h *Handler) resolveBreaker() (breaker, bool) {
	if h == nil || h.Auth == nil {
		return nil, false
	}
	b, ok := h.Auth.(breaker)
	return b, ok
}

func formatUntil(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
