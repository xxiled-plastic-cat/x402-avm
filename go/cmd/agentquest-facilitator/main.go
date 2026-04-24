package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	x402 "github.com/coinbase/x402/go"
	"github.com/coinbase/x402/go/extensions/avmsplit"
)

type facilitatorRequest struct {
	X402Version         int             `json:"x402Version"`
	PaymentPayload      json.RawMessage `json:"paymentPayload"`
	PaymentRequirements json.RawMessage `json:"paymentRequirements"`
}

func validatePaymentPayloadStructure(payloadBytes json.RawMessage) error {
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("payment_payload_invalid_json: %w", err)
	}
	accepted, ok := payload["accepted"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("payment_payload_accepted_required")
	}
	if stringField(accepted, "asset") == "" {
		return fmt.Errorf("payment_payload_accepted_asset_required")
	}
	if stringField(accepted, "amount") == "" {
		return fmt.Errorf("payment_payload_accepted_amount_required")
	}
	if stringField(accepted, "payTo") == "" {
		return fmt.Errorf("payment_payload_accepted_payto_required")
	}
	payloadField, ok := payload["payload"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("payment_payload_payload_required")
	}
	paymentGroup, ok := payloadField["paymentGroup"].([]interface{})
	if !ok || len(paymentGroup) == 0 {
		return fmt.Errorf("payment_payload_paymentgroup_required")
	}
	paymentIndexRaw, ok := payloadField["paymentIndex"]
	if !ok {
		return fmt.Errorf("payment_payload_paymentindex_required")
	}
	paymentIndexFloat, ok := paymentIndexRaw.(float64)
	if !ok {
		return fmt.Errorf("payment_payload_paymentindex_invalid")
	}
	paymentIndex := int(paymentIndexFloat)
	if paymentIndex < 0 || paymentIndex >= len(paymentGroup) {
		return fmt.Errorf("payment_payload_paymentindex_out_of_bounds")
	}
	for idx, entry := range paymentGroup {
		encoded, ok := entry.(string)
		if !ok || encoded == "" {
			return fmt.Errorf("payment_payload_paymentgroup_%d_invalid", idx)
		}
		if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
			return fmt.Errorf("payment_payload_paymentgroup_%d_not_base64: %w", idx, err)
		}
	}
	return nil
}

func stringField(raw map[string]interface{}, key string) string {
	if value, ok := raw[key].(string); ok {
		return value
	}
	return ""
}

func extractPayer(payloadBytes json.RawMessage) string {
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return ""
	}
	if payer := stringField(payload, "payer"); payer != "" {
		return payer
	}
	if nested, ok := payload["payload"].(map[string]interface{}); ok {
		return stringField(nested, "payer")
	}
	return ""
}

func extractNetwork(requirementsBytes json.RawMessage) string {
	var requirements map[string]interface{}
	if err := json.Unmarshal(requirementsBytes, &requirements); err != nil {
		return ""
	}
	return stringField(requirements, "network")
}

func parsePaymentGroup(payloadBytes json.RawMessage) ([][]byte, int, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, 0, fmt.Errorf("payment_payload_invalid_json: %w", err)
	}
	payloadField, ok := payload["payload"].(map[string]interface{})
	if !ok {
		return nil, 0, fmt.Errorf("payment_payload_payload_required")
	}
	paymentGroupRaw, ok := payloadField["paymentGroup"].([]interface{})
	if !ok || len(paymentGroupRaw) == 0 {
		return nil, 0, fmt.Errorf("payment_payload_paymentgroup_required")
	}
	paymentIndexRaw, ok := payloadField["paymentIndex"].(float64)
	if !ok {
		return nil, 0, fmt.Errorf("payment_payload_paymentindex_invalid")
	}
	paymentIndex := int(paymentIndexRaw)
	if paymentIndex < 0 || paymentIndex >= len(paymentGroupRaw) {
		return nil, 0, fmt.Errorf("payment_payload_paymentindex_out_of_bounds")
	}

	paymentGroup := make([][]byte, 0, len(paymentGroupRaw))
	for idx, entry := range paymentGroupRaw {
		encoded, ok := entry.(string)
		if !ok || strings.TrimSpace(encoded) == "" {
			return nil, 0, fmt.Errorf("payment_payload_paymentgroup_%d_invalid", idx)
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, 0, fmt.Errorf("payment_payload_paymentgroup_%d_not_base64: %w", idx, err)
		}
		paymentGroup = append(paymentGroup, decoded)
	}
	return paymentGroup, paymentIndex, nil
}

func resolveAlgodURL(network string) string {
	if fromEnv := strings.TrimSpace(os.Getenv("ALGORAND_RPC_URL")); fromEnv != "" {
		return fromEnv
	}
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "mainnet":
		return "https://mainnet-api.algonode.cloud"
	case "localnet":
		return "http://localhost:4001"
	case "testnet":
		fallthrough
	default:
		return "https://testnet-api.algonode.cloud"
	}
}

func resolveAlgodToken() string {
	return strings.TrimSpace(os.Getenv("ALGORAND_RPC_TOKEN"))
}

func submitAndConfirmPaymentGroup(network string, paymentGroup [][]byte) (string, error) {
	algodClient, err := algod.MakeClient(resolveAlgodURL(network), resolveAlgodToken())
	if err != nil {
		return "", fmt.Errorf("algod_client_init_failed: %w", err)
	}
	rawSignedGroup := make([]byte, 0)
	for _, signedTxn := range paymentGroup {
		rawSignedGroup = append(rawSignedGroup, signedTxn...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	submitResp, err := algodClient.SendRawTransaction(rawSignedGroup).Do(ctx)
	if err != nil {
		return "", fmt.Errorf("algod_send_raw_transaction_failed: %w", err)
	}
	txID := strings.TrimSpace(submitResp)
	if txID == "" {
		return "", fmt.Errorf("algod_send_raw_transaction_missing_txid")
	}

	status, err := algodClient.Status().Do(ctx)
	if err != nil {
		return "", fmt.Errorf("algod_status_failed: %w", err)
	}
	lastRound := status.LastRound
	for i := 0; i < 20; i++ {
		pending, _, err := algodClient.PendingTransactionInformation(txID).Do(ctx)
		if err == nil && pending.ConfirmedRound > 0 {
			return txID, nil
		}
		if _, err := algodClient.StatusAfterBlock(lastRound + 1).Do(ctx); err != nil {
			return "", fmt.Errorf("algod_wait_for_block_failed: %w", err)
		}
		lastRound++
	}
	return "", fmt.Errorf("transaction_not_confirmed_in_time: txid=%s", txID)
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req facilitatorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %s"}`, err), http.StatusBadRequest)
		return
	}
	if err := validatePaymentPayloadStructure(req.PaymentPayload); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"isValid":        false,
			"invalidReason":  "payment_payload_invalid",
			"invalidMessage": err.Error(),
			"payer":          extractPayer(req.PaymentPayload),
		})
		return
	}
	_, err := avmsplit.ValidateQuoteRequirementsFromRequirementsBytes(req.PaymentRequirements, time.Now().UTC())
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"isValid":        false,
			"invalidReason":  "avm_split_validation_failed",
			"invalidMessage": err.Error(),
			"payer":          extractPayer(req.PaymentPayload),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"isValid": true,
		"payer":   extractPayer(req.PaymentPayload),
	})
}

func handleSettle(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req facilitatorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %s"}`, err), http.StatusBadRequest)
		return
	}
	if err := validatePaymentPayloadStructure(req.PaymentPayload); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      false,
			"errorReason":  "payment_payload_invalid",
			"errorMessage": err.Error(),
			"payer":        extractPayer(req.PaymentPayload),
			"network":      extractNetwork(req.PaymentRequirements),
			"transaction":  "",
		})
		return
	}
	paymentGroup, paymentIndex, err := parsePaymentGroup(req.PaymentPayload)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      false,
			"errorReason":  "payment_payload_invalid",
			"errorMessage": err.Error(),
			"payer":        extractPayer(req.PaymentPayload),
			"network":      extractNetwork(req.PaymentRequirements),
			"transaction":  "",
		})
		return
	}
	now := time.Now().UTC()
	quote, err := avmsplit.ValidateQuoteRequirementsFromRequirementsBytes(req.PaymentRequirements, now)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      false,
			"errorReason":  "avm_split_validation_failed",
			"errorMessage": err.Error(),
			"payer":        extractPayer(req.PaymentPayload),
			"network":      extractNetwork(req.PaymentRequirements),
			"transaction":  "",
		})
		return
	}

	payer := extractPayer(req.PaymentPayload)
	network := extractNetwork(req.PaymentRequirements)
	txID, err := submitAndConfirmPaymentGroup(network, paymentGroup)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      false,
			"errorReason":  "algod_settlement_failed",
			"errorMessage": err.Error(),
			"payer":        payer,
			"network":      network,
			"transaction":  "",
			"paymentIndex": paymentIndex,
		})
		return
	}
	log.Printf("settled on-chain txid=%s network=%s payer=%s paymentIndex=%d", txID, network, payer, paymentIndex)
	response := map[string]interface{}{
		"success":      true,
		"payer":        payer,
		"transaction":  txID,
		"network":      network,
		"paymentIndex": paymentIndex,
	}
	if quote != nil {
		sharedSecret := os.Getenv("FACILITATOR_PROOF_SHARED_SECRET")
		if sharedSecret != "" {
			proofHeader, proofErr := avmsplit.BuildProofHeaderFromSettlement(
				req.PaymentRequirements,
				&x402.SettleResponse{
					Success:     true,
					Payer:       payer,
					Transaction: txID,
					Network:     x402.Network(network),
				},
				sharedSecret,
				func() time.Time { return now },
			)
			if proofErr == nil {
				response["proofHeader"] = proofHeader
			}
		}
	}

	_ = json.NewEncoder(w).Encode(response)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4022"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/verify", handleVerify)
	mux.HandleFunc("/settle", handleSettle)
	addr := ":" + port
	log.Printf("agentquest facilitator listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
