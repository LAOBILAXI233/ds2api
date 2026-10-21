package signin

import (
	"github.com/go-chi/chi/v5"
)

func RegisterRoutes(r chi.Router, h *Handler) {
	r.Get("/signin-risk", h.getSigninRisk)
	r.Post("/signin-risk/clear", h.clearSigninRisk)
}
