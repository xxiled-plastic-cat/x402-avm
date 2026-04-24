package avmsplit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	x402 "github.com/coinbase/x402/go"
)

// BeforeVerifyHook enforces quote-bound split requirements during facilitator verification.
func BeforeVerifyHook(now func() time.Time) x402.FacilitatorBeforeVerifyHook {
	return func(ctx x402.FacilitatorVerifyContext) (*x402.FacilitatorBeforeHookResult, error) {
		_, err := ValidateQuoteRequirementsFromRequirementsBytes(ctx.RequirementsBytes, now().UTC())
		if err != nil {
			return nil, x402.NewVerifyError("avm_split_validation_failed", "", err.Error())
		}
		return nil, nil
	}
}

// RegisterOnFacilitator wires split validation hooks onto a facilitator instance.
// This uses reflection so callers can pass the unexported concrete facilitator type
// returned by x402.Newx402Facilitator().
func RegisterOnFacilitator(facilitator interface{}, now func() time.Time) error {
	value := reflect.ValueOf(facilitator)
	verifyMethod := value.MethodByName("OnBeforeVerify")
	settleMethod := value.MethodByName("OnBeforeSettle")
	if !verifyMethod.IsValid() || !settleMethod.IsValid() {
		return fmt.Errorf("facilitator does not expose expected hook registration methods")
	}
	verifyMethod.Call([]reflect.Value{reflect.ValueOf(BeforeVerifyHook(now))})
	settleMethod.Call([]reflect.Value{reflect.ValueOf(BeforeSettleHook(now))})
	return nil
}

// BeforeSettleHook enforces quote-bound split requirements before settlement.
func BeforeSettleHook(now func() time.Time) x402.FacilitatorBeforeSettleHook {
	return func(ctx x402.FacilitatorSettleContext) (*x402.FacilitatorBeforeHookResult, error) {
		_, err := ValidateQuoteRequirementsFromRequirementsBytes(ctx.RequirementsBytes, now().UTC())
		if err != nil {
			return nil, x402.NewSettleError(
				"avm_split_validation_failed",
				"",
				x402.Network(ctx.Requirements.GetNetwork()),
				"",
				err.Error(),
			)
		}
		return nil, nil
	}
}

// BuildProofHeaderFromSettlement builds a base64 proof header payload from
// facilitator settlement output. Caller should attach this to trusted upstream
// headers (e.g., X-AQ-Settlement-Proof).
func BuildProofHeaderFromSettlement(
	requirementsBytes []byte,
	settle *x402.SettleResponse,
	sharedSecret string,
	now func() time.Time,
) (string, error) {
	if settle == nil {
		return "", fmt.Errorf("settlement result is required")
	}
	req, err := ValidateQuoteRequirementsFromRequirementsBytes(requirementsBytes, now().UTC())
	if err != nil {
		return "", err
	}
	if req == nil {
		return "", fmt.Errorf("avm split quote requirements not present")
	}
	proof, err := BuildSettlementProof(
		*req,
		settle.Payer,
		settle.Transaction,
		now().UTC(),
		sharedSecret,
	)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", fmt.Errorf("failed to marshal settlement proof: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
