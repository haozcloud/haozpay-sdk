package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
)

type PaymentService struct {
	client *resty.Client
	config *Config
}

func NewPaymentService(client *resty.Client, config *Config) *PaymentService {
	return &PaymentService{
		client: client,
		config: config,
	}
}

func (s *PaymentService) CreateOrder(ctx context.Context, req *CreatePaymentOrderRequest) (*PaymentOrderResponse, error) {
	bizBodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bizBody: %w", err)
	}

	haozReq := &HaozPayRequest{
		MerchantNo: s.config.MerchantNo,
		Timestamp:  currentTimestampMillis(),
		BizBody:    string(bizBodyBytes),
	}

	var result struct {
		Response
		Data *PaymentOrderResponse `json:"data"`
	}

	_, err = s.client.R().
		SetContext(ctx).
		SetBody(haozReq).
		SetResult(&result).
		Post("/pay-core/payment/order")

	if err != nil {
		return nil, fmt.Errorf("failed to create payment order: %w", err)
	}

	if result.Code != 0 {
		return nil, NewSDKError(
			result.Code,
			result.Message,
			0,
		)
	}

	return result.Data, nil
}

func (s *PaymentService) CancelOrder(ctx context.Context, req *CancelPaymentOrderRequest) error {
	bizBodyBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal bizBody: %w", err)
	}

	haozReq := &HaozPayRequest{
		MerchantNo: s.config.MerchantNo,
		Timestamp:  currentTimestampMillis(),
		BizBody:    string(bizBodyBytes),
	}

	var result Response

	_, err = s.client.R().
		SetContext(ctx).
		SetBody(haozReq).
		SetResult(&result).
		Post("/pay-core/payment/cancel")

	if err != nil {
		return fmt.Errorf("failed to cancel payment order: %w", err)
	}

	if result.Code != 0 {
		return NewSDKError(
			result.Code,
			result.Message,
			0,
		)
	}

	return nil
}

func (s *PaymentService) CreateRefund(ctx context.Context, req *CreateRefundRequest) (*RefundResponse, error) {
	bizBodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bizBody: %w", err)
	}

	haozReq := &HaozPayRequest{
		MerchantNo: s.config.MerchantNo,
		Timestamp:  currentTimestampMillis(),
		BizBody:    string(bizBodyBytes),
	}

	var result struct {
		Response
		Data *RefundResponse `json:"data"`
	}

	_, err = s.client.R().
		SetContext(ctx).
		SetBody(haozReq).
		SetResult(&result).
		Post("/pay-core/payment/refund")

	if err != nil {
		return nil, fmt.Errorf("failed to create refund: %w", err)
	}

	if result.Code != 0 {
		return nil, NewSDKError(
			result.Code,
			result.Message,
			0,
		)
	}

	return result.Data, nil
}

func (s *PaymentService) QueryRefund(ctx context.Context, req *QueryRefundRequest) (*QueryRefundResponse, error) {
	bizBodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bizBody: %w", err)
	}

	haozReq := &HaozPayRequest{
		MerchantNo: s.config.MerchantNo,
		Timestamp:  currentTimestampMillis(),
		BizBody:    string(bizBodyBytes),
	}

	var result struct {
		Response
		Data *QueryRefundResponse `json:"data"`
	}

	_, err = s.client.R().
		SetContext(ctx).
		SetBody(haozReq).
		SetResult(&result).
		Post("/pay-core/payment/refund/query")

	if err != nil {
		return nil, fmt.Errorf("failed to query refund: %w", err)
	}

	if result.Code != 0 {
		return nil, NewSDKError(
			result.Code,
			result.Message,
			0,
		)
	}

	return result.Data, nil
}

func (s *PaymentService) CreateWithdraw(ctx context.Context, req *CreateWithdrawRequest) error {
	bizBodyBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal bizBody: %w", err)
	}

	haozReq := &HaozPayRequest{
		MerchantNo: s.config.MerchantNo,
		Timestamp:  currentTimestampMillis(),
		BizBody:    string(bizBodyBytes),
	}

	var result Response

	_, err = s.client.R().
		SetContext(ctx).
		SetBody(haozReq).
		SetResult(&result).
		Post("/pay-core/account/withdraw")

	if err != nil {
		return fmt.Errorf("failed to create withdraw: %w", err)
	}

	if result.Code != 0 {
		return NewSDKError(
			result.Code,
			result.Message,
			0,
		)
	}

	return nil
}

func currentTimestampMillis() int64 {
	return time.Now().UnixMilli()
}
