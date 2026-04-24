package avmsplit

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	x402 "github.com/coinbase/x402/go"
)

func TestValidateQuoteRequirements(t *testing.T) {
	now := time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	valid := QuoteRequirements{
		QuoteID:           "q-1",
		ActionFingerprint: "abc123",
		AssetID:           "31566704",
		Network:           "algorand-mainnet",
		Nonce:             "n-1",
		ExpiresAt:         now.Add(2 * time.Minute).Format(time.RFC3339),
		Split: []SplitRecipient{
			{Role: "merchant", Address: "ADDR1", Amount: "900"},
			{Role: "platform", Address: "ADDR2", Amount: "100"},
		},
	}
	if err := ValidateQuoteRequirements(valid, now); err != nil {
		t.Fatalf("expected valid quote requirements, got %v", err)
	}

	expired := valid
	expired.ExpiresAt = now.Add(-1 * time.Minute).Format(time.RFC3339)
	if err := ValidateQuoteRequirements(expired, now); err == nil {
		t.Fatalf("expected expiry validation error")
	}
}

func TestValidateQuoteRequirementsFromRequirementsBytes(t *testing.T) {
	now := time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	requirements := map[string]interface{}{
		"network": "algorand-mainnet",
		"extra": map[string]interface{}{
			"avmSplitQuote": map[string]interface{}{
				"quoteId":           "q-1",
				"actionFingerprint": "abc123",
				"assetId":           "31566704",
				"network":           "algorand-mainnet",
				"nonce":             "n-1",
				"expiresAt":         now.Add(2 * time.Minute).Format(time.RFC3339),
				"split": []map[string]string{
					{"role": "merchant", "address": "ADDR1", "amount": "900"},
					{"role": "platform", "address": "ADDR2", "amount": "100"},
				},
			},
		},
	}
	raw, err := json.Marshal(requirements)
	if err != nil {
		t.Fatalf("marshal requirements: %v", err)
	}
	parsed, err := ValidateQuoteRequirementsFromRequirementsBytes(raw, now)
	if err != nil {
		t.Fatalf("expected requirements to validate, got %v", err)
	}
	if parsed == nil || parsed.QuoteID != "q-1" {
		t.Fatalf("expected parsed quote q-1, got %#v", parsed)
	}
}

func TestBuildProofHeaderFromSettlement(t *testing.T) {
	now := time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	requirements := map[string]interface{}{
		"quoteId":           "q-1",
		"actionFingerprint": "abc123",
		"assetId":           "31566704",
		"network":           "algorand-mainnet",
		"nonce":             "n-1",
		"expiresAt":         now.Add(2 * time.Minute).Format(time.RFC3339),
		"split": []map[string]string{
			{"role": "merchant", "address": "ADDR1", "amount": "900"},
			{"role": "platform", "address": "ADDR2", "amount": "100"},
		},
	}
	rawRequirements, err := json.Marshal(requirements)
	if err != nil {
		t.Fatalf("marshal requirements: %v", err)
	}
	header, err := BuildProofHeaderFromSettlement(
		rawRequirements,
		&x402.SettleResponse{
			Success:     true,
			Payer:       "PAYER",
			Transaction: "TXID",
			Network:     x402.Network("algorand-mainnet"),
		},
		"test-secret",
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("expected proof header, got %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var proof SettlementProof
	if err := json.Unmarshal(decoded, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	if proof.QuoteID != "q-1" || proof.Signature == "" {
		t.Fatalf("unexpected proof output: %#v", proof)
	}
}
