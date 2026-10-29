package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"go.uber.org/zap"

	"go.opentelemetry.io/otel/trace"

	"github.com/eliezerraj/go-core/v3/httpclient"
	"github.com/eliezerraj/go-core/v3/logger"

	"github.com/go-authorizer-v2/application/domain/entity"
	"github.com/go-authorizer-v2/application/tracing"
	"github.com/go-authorizer-v2/application/domain/apperrors"
)

const RequestIDHeaderName = "x-request-id"

type AuthModule struct {
	client				httpclient.IHTTPClient
}

func NewAuthModule(	client httpclient.IHTTPClient ) AuthModule {
	logger.Info(context.Background(), "module auth NewAuthModule called with authClientService SUCCESSFULLY")

	return AuthModule{
		client: client,
	}
}

func (im *AuthModule) GetJwks(ctx context.Context, endpoint string) (*entity.WellKnownJwks, error) {
	logger.Info(ctx, "module auth GetJwks called")

	ctxHttpTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Trace
	ctx, span := tracing.CustomStartSpanCtx(ctxHttpTimeout, "module.auth.getJwks", trace.SpanKindInternal)
	defer span.End()


	logger.Info(ctx, "module auth GetJwks request", zap.String("method", http.MethodGet), zap.String("endpoint", endpoint))
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		logger.Error(ctx, "module auth GetJwks failed to create request", zap.Error(err))
		return nil, err
	}
	
	// Set headers for the request. the const are in auth_module.go file
	xrequestid, ok := ctx.Value(RequestIDHeaderName).(string)
	if !ok {
		xrequestid = "not-informed"
	}

	headers := map[string]string{
		"Connection":  "keep-alive",
		"Accept":      "application/json",
		"Content-Type": "application/json",
		"Keep-Alive": "timeout=5, max=1000",
		"x-request-id": xrequestid,
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := im.client.Do(req.WithContext(ctx))
	if err != nil {
		logger.Error(ctx, "module auth GetJwks failed to perform request", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue processing
	case http.StatusNotFound:
		logger.Warn(ctx, "Auth service returned with status", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("auth service returned with status: %d: %w", resp.StatusCode, apperrors.ErrNotFound)
	default:
		logger.Error(ctx, "Auth service returned unexpected status", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("auth service returned status: %d", resp.StatusCode)
	}

	// Decode the response body into the JWKS set, which contains a keys array.
	var res entity.WellKnownJwks
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		logger.Error(ctx, "module auth GetJwks failed to decode response", zap.Error(err))
		return nil, err
	}

	return &res, nil
}

func (im *AuthModule) GetClientMetadata(ctx context.Context, endpoint string) (*entity.ClientMetadata, error) {
	logger.Info(ctx, "module auth GetClientMetadata called", zap.String("endpoint", endpoint))

	ctxHttpTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ctx, span := tracing.CustomStartSpanCtx(ctxHttpTimeout, "module.auth.getClientMetadata", trace.SpanKindInternal)
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		logger.Error(ctx, "module auth GetClientMetadata failed to create request", zap.Error(err))
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := im.client.Do(req)
	if err != nil {
		logger.Error(ctx, "module auth GetClientMetadata failed to perform request", zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error(ctx, "client metadata endpoint returned unexpected status", zap.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("client metadata endpoint returned status: %d", resp.StatusCode)
	}

	var metadata entity.ClientMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		logger.Error(ctx, "module auth GetClientMetadata failed to decode response", zap.Error(err))
		return nil, err
	}

	return &metadata, nil
}
