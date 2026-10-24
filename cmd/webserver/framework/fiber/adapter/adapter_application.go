package adapter

import (
	"context"
	"encoding/base64"
	"strings"

	"go.uber.org/zap"

	"github.com/go-authorizer-v2/application/config"
	"github.com/go-authorizer-v2/application/infrastructure/application"
	"github.com/go-authorizer-v2/application/domain/external"
	"github.com/go-authorizer-v2/application/tracing"

	"github.com/eliezerraj/go-core/v3/logger"
	"github.com/eliezerraj/go-core/v3/http/utils"

	"github.com/gofiber/fiber/v3"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/attribute"
)

type ApplicationAdapter struct {
	cfg *config.Config
	application *application.Application
}

func parseBasicAuth(header string) (string, string, bool) {
	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	clientID, secret, found := strings.Cut(string(decoded), ":")
	return clientID, secret, found
}

func NewApplicationAdapter(cfg *config.Config, application *application.Application) *ApplicationAdapter {
	logger.Info(context.Background(), "initializing application adapter SUCCESSFULLY")

	return &ApplicationAdapter{
		cfg:         cfg,
		application: application,
	}
}

func (a *ApplicationAdapter) Login(ctxFiber fiber.Ctx) error {
	logger.Info(ctxFiber.Context(), "Login called")

	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.Context(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "adapter.login", trace.SpanKindInternal)
	defer span.End()

	logger.Debug(
		ctx,
		a.cfg.App.Name,
		zap.ByteString("headers", utils.FormatHeadersAsJSON(ctxFiber.GetReqHeaders())),
		zap.String("host", ctxFiber.Hostname()),
		zap.String("path", ctxFiber.Path()),
		zap.ByteString("query", ctxFiber.Request().URI().QueryString()),
		zap.ByteString("body", ctxFiber.Body()),
	)

	loginReq := external.LoginRequest{}
	if err := ctxFiber.Bind().Body(&loginReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusBadRequest),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}
	
	accessToken, err := a.application.AuthorizerController.Login(ctx, loginReq)
	if err != nil {
		logger.Error(ctx, "failed to login", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusUnauthorized,
			fiber.ErrUnauthorized,
			fiber.ErrUnauthorized.Message,
			"failed to login",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusUnauthorized),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	span.SetAttributes(
			attribute.Int("http.response.status_code", fiber.StatusOK),
	)
	return ctxFiber.Status(fiber.StatusOK).JSON(accessToken)
}

func (a *ApplicationAdapter) VerifyJWT(ctxFiber fiber.Ctx) error {
	logger.Info(ctxFiber.Context(), "VerifyJWT called")

	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.Context(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "adapter.verifyJWT", trace.SpanKindInternal)
	defer span.End()

	logger.Debug(
		ctx,
		a.cfg.App.Name,
		zap.ByteString("headers", utils.FormatHeadersAsJSON(ctxFiber.GetReqHeaders())),
		zap.String("host", ctxFiber.Hostname()),
		zap.String("path", ctxFiber.Path()),
		zap.ByteString("query", ctxFiber.Request().URI().QueryString()),
		zap.ByteString("body", ctxFiber.Body()),
	)

	verifyJWTReq := external.VerifyJWTRequest{}
	if err := ctxFiber.Bind().Body(&verifyJWTReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusBadRequest),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	claims, err := a.application.AuthorizerController.VerifyJWT(ctx, verifyJWTReq)
	if err != nil {
		logger.Error(ctx, "failed to verify JWT", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusUnauthorized,
			fiber.ErrUnauthorized,
			fiber.ErrUnauthorized.Message,
			"failed to verify JWT",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusUnauthorized),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	resp := external.VerifyJWTResponse{
		Response: "JWT verification successful",
		Claims:   claims,
	}

	span.SetAttributes(
			attribute.Int("http.response.status_code", fiber.StatusOK),
	)
	return ctxFiber.Status(fiber.StatusOK).JSON(resp)
}

func (a *ApplicationAdapter) WellKnownJwksGet(ctxFiber fiber.Ctx) error {
	logger.Info(ctxFiber.Context(), "WellKnownJwksGet called")

	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.Context(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "adapter.wellKnownJwksGet", trace.SpanKindInternal)
	defer span.End()

	logger.Debug(
		ctx,
		a.cfg.App.Name,
		zap.ByteString("headers", utils.FormatHeadersAsJSON(ctxFiber.GetReqHeaders())),
		zap.String("host", ctxFiber.Hostname()),
		zap.String("path", ctxFiber.Path()),
		zap.ByteString("query", ctxFiber.Request().URI().QueryString()),
	)

	jwks, err := a.application.AuthorizerController.WellKnownJwksGet(ctx)
	if err != nil {
		logger.Error(ctx, "failed to get JWKS", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusInternalServerError,
			fiber.ErrInternalServerError,
			fiber.ErrInternalServerError.Message,
			"failed to get JWKS",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusInternalServerError),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}
	span.SetAttributes(
			attribute.Int("http.response.status_code", fiber.StatusOK),
	)
	return ctxFiber.Status(fiber.StatusOK).JSON(jwks)
}

func (a *ApplicationAdapter) RefreshToken(ctxFiber fiber.Ctx) error {
	logger.Info(ctxFiber.Context(), "RefreshToken called")

	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.Context(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "adapter.refreshToken", trace.SpanKindInternal)
	defer span.End()

	logger.Debug(
		ctx,
		a.cfg.App.Name,
		zap.ByteString("headers", utils.FormatHeadersAsJSON(ctxFiber.GetReqHeaders())),
		zap.String("host", ctxFiber.Hostname()),
		zap.String("path", ctxFiber.Path()),
		zap.ByteString("query", ctxFiber.Request().URI().QueryString()),
	)

	verifyJWTReq := external.VerifyJWTRequest{}
	if err := ctxFiber.Bind().Body(&verifyJWTReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusBadRequest),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	// Pass the parsed request to the controller
	tokenRefreshed, err := a.application.AuthorizerController.RefreshToken(ctx, verifyJWTReq)
	if err != nil {
		logger.Error(ctx, "failed to refresh token", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusInternalServerError,
			fiber.ErrInternalServerError,
			fiber.ErrInternalServerError.Message,
			"failed to refresh token",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusInternalServerError),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}
	span.SetAttributes(
			attribute.Int("http.response.status_code", fiber.StatusOK),
	)
	return ctxFiber.Status(fiber.StatusOK).JSON(tokenRefreshed)
}

// VerifyES256JWT handles the verification of ES256 JWT tokens.
func (a *ApplicationAdapter) VerifyES256JWT(ctxFiber fiber.Ctx) error {
	logger.Info(ctxFiber.Context(), "VerifyES256JWT called")

	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.Context(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "adapter.verifyES256JWT", trace.SpanKindInternal)
	defer span.End()

	logger.Debug(
		ctx,
		a.cfg.App.Name,
		zap.ByteString("headers", utils.FormatHeadersAsJSON(ctxFiber.GetReqHeaders())),
		zap.String("host", ctxFiber.Hostname()),
		zap.String("path", ctxFiber.Path()),
		zap.ByteString("query", ctxFiber.Request().URI().QueryString()),
		zap.ByteString("body", ctxFiber.Body()),
	)

	verifyJWTReq := external.VerifyJWTRequest{}
	if err := ctxFiber.Bind().Body(&verifyJWTReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusBadRequest),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	// Pass the parsed request to the controller
	claims, err := a.application.AuthorizerController.VerifyES256JWT(ctx, verifyJWTReq)
	if err != nil {
		logger.Error(ctx, "failed to verify ES256 JWT", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusInternalServerError,
			fiber.ErrInternalServerError,
			fiber.ErrInternalServerError.Message,
			"failed to verify ES256 JWT",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusInternalServerError),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}
	span.SetAttributes(
			attribute.Int("http.response.status_code", fiber.StatusOK),
	)
	return ctxFiber.Status(fiber.StatusOK).JSON(claims)
}

// AuthToken handles the /auth/token endpoint for obtaining an authentication token.
func (a *ApplicationAdapter) AuthToken(ctxFiber fiber.Ctx) error {
	logger.Info(ctxFiber.Context(), "AuthToken called")

	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.Context(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "adapter.authToken", trace.SpanKindInternal)
	defer span.End()

	logger.Info(
		ctx,
		a.cfg.App.Name,
		zap.ByteString("headers", utils.FormatHeadersAsJSON(ctxFiber.GetReqHeaders())),
		zap.String("host", ctxFiber.Hostname()),
		zap.String("path", ctxFiber.Path()),
		zap.ByteString("query", ctxFiber.Request().URI().QueryString()),
		zap.ByteString("body", ctxFiber.Body()),
	)

	authTokenReq := external.AuthTokenRequest{}
	if err := ctxFiber.Bind().Form(&authTokenReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusBadRequest),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	// Client credentials come from the Basic Authorization header (RFC 6749 2.3.1)
	if clientID, secret, ok := parseBasicAuth(ctxFiber.Get(fiber.HeaderAuthorization)); ok {
		authTokenReq.ClientID = clientID
		authTokenReq.SecretID = secret
		authTokenReq.IsBasicAuth = true
	}

	// Pass the parsed request to the controller
	token, err := a.application.AuthorizerController.GrantType(ctx, authTokenReq)
	if err != nil {
		logger.Error(ctx, "failed to get auth token", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusInternalServerError,
			fiber.ErrInternalServerError,
			fiber.ErrInternalServerError.Message,
			"failed to get auth token",
			err.Error(),
			external.BUSSINESS_ERROR)
		span.SetAttributes(
				attribute.Int("http.response.status_code", fiber.StatusInternalServerError),
		)
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}
	span.SetAttributes(
			attribute.Int("http.response.status_code", fiber.StatusOK),
	)
	return ctxFiber.Status(fiber.StatusOK).JSON(token)
}