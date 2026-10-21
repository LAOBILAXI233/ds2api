package auth

import (
	"context"
	"testing"
	"time"
)

// The web client's own error enum lists 13 (SIGNATURE_REQUIRED) and 14
// (OTP_REQUIRED): a device that has to be verified by a person. A gateway cannot
// answer them, so they must not be retried as if they were transient — but the
// account is fine, so it must not be retired either.
func TestHumanVerificationRefusalsAreTerminal(t *testing.T) {
	for _, code := range []int{LoginCodeMobileRestricted, LoginCodeSignature, LoginCodeOTP} {
		if !IsTerminalLoginCode(code) {
			t.Fatalf("code %d must be terminal (retrying cannot change it)", code)
		}
	}
	if !NeedsHumanVerification(LoginCodeSignature) || !NeedsHumanVerification(LoginCodeOTP) {
		t.Fatal("13/14 must be reported as needing human verification")
	}
	if NeedsHumanVerification(LoginCodeDevice) {
		t.Fatal("a device risk refusal is not a verification request")
	}
}

func TestSignatureRequiredParksAccountWithoutRetiringIt(t *testing.T) {
	h := newRefreshHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd"}]}`,
		func(int32) (string, error) {
			return "", NewLoginError(LoginCodeSignature, "SIGNATURE_REQUIRED")
		})

	acc := h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonRequest); err == nil {
		t.Fatal("expected the refusal to surface")
	}

	parked := h.account("a@example.com")
	if parked.Disabled {
		t.Fatal("an unverified device must not retire the account")
	}
	if parked.CooldownUntil <= float64(time.Now().Unix()) {
		t.Fatalf("expected the account to be parked, got cooldown=%v", parked.CooldownUntil)
	}
	if parked.RefreshError == "" {
		t.Fatal("expected the reason to name the verification step")
	}
	// The account is parked, so the pool stops scheduling it.
	if parked.IsSchedulable() {
		t.Fatal("a parked account must not be schedulable")
	}
}

// A restricted mobile number is an account-level verdict: no amount of waiting
// or re-verifying fixes it, so it retires the account for an operator to handle.
func TestMobileRestrictedRetiresAccount(t *testing.T) {
	h := newRefreshHarness(t, `{"accounts":[{"email":"a@example.com","password":"pwd"}]}`,
		func(int32) (string, error) {
			return "", NewLoginError(LoginCodeMobileRestricted, "MOBILE_RESTRICTED")
		})

	acc := h.account("a@example.com")
	if err := h.resolver.RefreshAccountToken(context.Background(), acc, refreshReasonRequest); err == nil {
		t.Fatal("expected the refusal to surface")
	}
	retired := h.account("a@example.com")
	if !retired.Disabled {
		t.Fatal("expected MOBILE_RESTRICTED to retire the account")
	}
	if retired.CooldownUntil != 0 {
		t.Fatalf("a retirement must not also park the account, got %v", retired.CooldownUntil)
	}
}
