package signin

// Sign-in risk state
//
// When upstream answers a sign-in with `RISK_DEVICE_DETECTED`, the resolver opens
// a circuit breaker and stops signing in for a cooldown window. From the console
// that state used to be invisible: every account simply looked unusable and the
// "available" counter sat at 0 with no explanation. These two endpoints are what
// the account page polls to say WHY nothing is being scheduled.
//
//   GET  /admin/signin-risk        breaker state (active, until, strikes)
//   POST /admin/signin-risk/clear  operator override: retry a sign-in now

import "net/http"

func (h *Handler) getSigninRisk(w http.ResponseWriter, _ *http.Request) {
	b, ok := h.resolveBreaker()
	if !ok {
		writeJSON(w, http.StatusOK, signinStatusPayload{Success: true, Supported: false})
		return
	}
	status := b.RiskStatus()
	writeJSON(w, http.StatusOK, signinStatusPayload{
		Success:          true,
		Supported:        true,
		Active:           status.Active,
		Strikes:          status.Strikes,
		RemainingSeconds: status.RemainingSeconds,
		Until:            formatUntil(status.Until),
	})
}

func (h *Handler) clearSigninRisk(w http.ResponseWriter, _ *http.Request) {
	b, ok := h.resolveBreaker()
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"detail": "当前运行环境不支持登录风控开关",
		})
		return
	}
	b.ClearRisk()
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
