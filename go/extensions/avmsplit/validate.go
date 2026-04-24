package avmsplit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

var (
	ErrQuoteIDRequired           = errors.New("avm_split_quote_id_required")
	ErrActionFingerprintRequired = errors.New("avm_split_action_fingerprint_required")
	ErrAssetIDRequired           = errors.New("avm_split_asset_id_required")
	ErrNetworkRequired           = errors.New("avm_split_network_required")
	ErrNonceRequired             = errors.New("avm_split_nonce_required")
	ErrExpirationRequired        = errors.New("avm_split_expires_at_required")
	ErrSplitRecipientsRequired   = errors.New("avm_split_recipients_required")
)

func parseQuoteRequirementsMap(raw map[string]interface{}) (*QuoteRequirements, bool, error) {
	_, hasQuote := raw["quoteId"]
	_, hasSplit := raw["split"]
	if !hasQuote && !hasSplit {
		return nil, false, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, false, fmt.Errorf("avm_split_quote_marshal_failed: %w", err)
	}
	var out QuoteRequirements
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, false, fmt.Errorf("avm_split_quote_unmarshal_failed: %w", err)
	}
	return &out, true, nil
}

// ExtractQuoteRequirementsFromRequirementsBytes extracts quote-bound split
// requirements from a payment requirements payload.
func ExtractQuoteRequirementsFromRequirementsBytes(requirementsBytes []byte) (*QuoteRequirements, bool, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(requirementsBytes, &raw); err != nil {
		return nil, false, fmt.Errorf("avm_split_requirements_unmarshal_failed: %w", err)
	}

	if parsed, ok, err := parseQuoteRequirementsMap(raw); ok || err != nil {
		return parsed, ok, err
	}
	if extraRaw, ok := raw["extra"].(map[string]interface{}); ok {
		if parsed, ok, err := parseQuoteRequirementsMap(extraRaw); ok || err != nil {
			return parsed, ok, err
		}
		if wrapped, ok := extraRaw["avmSplitQuote"].(map[string]interface{}); ok {
			return parseQuoteRequirementsMap(wrapped)
		}
	}
	return nil, false, nil
}

// ValidateQuoteRequirementsFromRequirementsBytes validates quote-bound split
// requirements if present in requirements bytes.
func ValidateQuoteRequirementsFromRequirementsBytes(requirementsBytes []byte, now time.Time) (*QuoteRequirements, error) {
	req, found, err := ExtractQuoteRequirementsFromRequirementsBytes(requirementsBytes)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	if err := ValidateQuoteRequirements(*req, now); err != nil {
		return nil, err
	}
	return req, nil
}

// ValidateQuoteRequirements validates split-quote envelope fields.
func ValidateQuoteRequirements(req QuoteRequirements, now time.Time) error {
	if req.QuoteID == "" {
		return ErrQuoteIDRequired
	}
	if req.ActionFingerprint == "" {
		return ErrActionFingerprintRequired
	}
	if req.AssetID == "" {
		return ErrAssetIDRequired
	}
	if req.Network == "" {
		return ErrNetworkRequired
	}
	if req.Nonce == "" {
		return ErrNonceRequired
	}
	if req.ExpiresAt == "" {
		return ErrExpirationRequired
	}
	if len(req.Split) == 0 {
		return ErrSplitRecipientsRequired
	}
	expiry, err := req.ExpirationTime()
	if err != nil {
		return fmt.Errorf("avm_split_expires_at_invalid: %w", err)
	}
	if !expiry.After(now) {
		return fmt.Errorf("avm_split_quote_expired: now=%s expires_at=%s", now.UTC().Format(time.RFC3339), req.ExpiresAt)
	}
	for i, recipient := range req.Split {
		if recipient.Role == "" {
			return fmt.Errorf("avm_split_recipient_%d_role_required", i)
		}
		if recipient.Address == "" {
			return fmt.Errorf("avm_split_recipient_%d_address_required", i)
		}
		if recipient.Amount == "" {
			return fmt.Errorf("avm_split_recipient_%d_amount_required", i)
		}
	}
	return nil
}

// BuildSettlementProof builds and signs a deterministic settlement proof.
func BuildSettlementProof(
	req QuoteRequirements,
	payer string,
	transaction string,
	settledAt time.Time,
	sharedSecret string,
) (SettlementProof, error) {
	if payer == "" {
		return SettlementProof{}, fmt.Errorf("avm_split_proof_payer_required")
	}
	if transaction == "" {
		return SettlementProof{}, fmt.Errorf("avm_split_proof_transaction_required")
	}
	if sharedSecret == "" {
		return SettlementProof{}, fmt.Errorf("avm_split_proof_shared_secret_required")
	}
	proof := SettlementProof{
		Version:           "aq-settlement-proof-v1",
		QuoteID:           req.QuoteID,
		ActionFingerprint: req.ActionFingerprint,
		AssetID:           req.AssetID,
		Network:           req.Network,
		Payer:             payer,
		Transaction:       transaction,
		Split:             req.Split,
		Nonce:             req.Nonce,
		ExpiresAt:         req.ExpiresAt,
		SettledAt:         settledAt.UTC().Format(time.RFC3339),
	}
	signature, err := SignSettlementProof(proof, sharedSecret)
	if err != nil {
		return SettlementProof{}, err
	}
	proof.Signature = signature
	return proof, nil
}

// SignSettlementProof computes proof signature.
func SignSettlementProof(proof SettlementProof, sharedSecret string) (string, error) {
	split := make([]SplitRecipient, len(proof.Split))
	copy(split, proof.Split)
	sort.Slice(split, func(i, j int) bool {
		left := split[i].Role + ":" + split[i].Address
		right := split[j].Role + ":" + split[j].Address
		return left < right
	})
	payload := struct {
		Version           string           `json:"version"`
		QuoteID           string           `json:"quoteId"`
		ActionFingerprint string           `json:"actionFingerprint"`
		AssetID           string           `json:"assetId"`
		Network           string           `json:"network"`
		Payer             string           `json:"payer"`
		Transaction       string           `json:"transaction"`
		Split             []SplitRecipient `json:"split"`
		Nonce             string           `json:"nonce"`
		ExpiresAt         string           `json:"expiresAt"`
		SettledAt         string           `json:"settledAt"`
	}{
		Version:           proof.Version,
		QuoteID:           proof.QuoteID,
		ActionFingerprint: proof.ActionFingerprint,
		AssetID:           proof.AssetID,
		Network:           proof.Network,
		Payer:             proof.Payer,
		Transaction:       proof.Transaction,
		Split:             split,
		Nonce:             proof.Nonce,
		ExpiresAt:         proof.ExpiresAt,
		SettledAt:         proof.SettledAt,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("avm_split_proof_marshal_failed: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
