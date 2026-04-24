package avmsplit

import (
	"context"
	"testing"
	"time"

	x402 "github.com/coinbase/x402/go"
)

func TestBeforeVerifyHookRejectsInvalidSplitQuote(t *testing.T) {
	hook := BeforeVerifyHook(func() time.Time {
		return time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	})
	_, err := hook(x402.FacilitatorVerifyContext{
		Ctx:               context.Background(),
		RequirementsBytes: []byte(`{"quoteId":"q-1","expiresAt":"2020-01-01T00:00:00Z","split":[]}`),
	})
	if err == nil {
		t.Fatal("expected hook to reject invalid quote requirements")
	}
}

func TestBeforeSettleHookAcceptsNoSplitQuote(t *testing.T) {
	hook := BeforeSettleHook(func() time.Time {
		return time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	})
	_, err := hook(x402.FacilitatorSettleContext{
		Ctx:               context.Background(),
		RequirementsBytes: []byte(`{"network":"algorand-mainnet","amount":"1000"}`),
	})
	if err != nil {
		t.Fatalf("expected hook to allow non-split requirements, got %v", err)
	}
}

func TestRegisterOnFacilitator(t *testing.T) {
	facilitator := x402.Newx402Facilitator()
	err := RegisterOnFacilitator(facilitator, time.Now)
	if err != nil {
		t.Fatalf("expected hook registration to succeed: %v", err)
	}
}
