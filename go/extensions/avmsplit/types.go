package avmsplit

import "time"

// SplitRecipient describes one required output in a split payment.
type SplitRecipient struct {
	Role    string `json:"role"`
	Address string `json:"address"`
	Amount  string `json:"amount"`
}

// QuoteRequirements is the quote-bound split requirement payload expected to be
// carried by the resource server and verified by the facilitator.
type QuoteRequirements struct {
	QuoteID           string           `json:"quoteId"`
	ActionFingerprint string           `json:"actionFingerprint"`
	AssetID           string           `json:"assetId"`
	Network           string           `json:"network"`
	Nonce             string           `json:"nonce"`
	ExpiresAt         string           `json:"expiresAt"`
	Split             []SplitRecipient `json:"split"`
}

// SettlementProof is a quote-bound proof envelope that can be propagated to
// protected upstream services after successful facilitator settlement.
type SettlementProof struct {
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
	Signature         string           `json:"signature"`
}

// ExpirationTime parses ExpiresAt as RFC3339.
func (q QuoteRequirements) ExpirationTime() (time.Time, error) {
	return time.Parse(time.RFC3339, q.ExpiresAt)
}
