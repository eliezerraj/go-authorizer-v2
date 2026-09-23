package adapter

import (
	"context"
	"go.uber.org/zap"

	"github.com/go-authorizer-v2/application/config"
	"github.com/go-authorizer-v2/application/infrastructure/application"
	"github.com/go-authorizer-v2/application/domain/external"
	"github.com/go-authorizer-v2/application/tracing"

	"github.com/eliezerraj/go-core/v3/logger"
	"github.com/eliezerraj/go-core/v3/http/utils"

	"github.com/gofiber/fiber/v2"

	"go.opentelemetry.io/otel/trace"
)

type ApplicationAdapter struct {
	cfg *config.Config
	application *application.Application
}

func NewApplicationAdapter(cfg *config.Config, application *application.Application) *ApplicationAdapter {
	logger.InfoOutCtx("initializing application adapter SUCCESSFULLY")

	return &ApplicationAdapter{
		cfg:         cfg,
		application: application,
	}
}

func (a *ApplicationAdapter) Login(ctxFiber *fiber.Ctx) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.UserContext(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "applicationAdapter.login", trace.SpanKindInternal)
	defer span.End()
	logger.Info(ctx, "Login called")

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
	if err := ctxFiber.BodyParser(&loginReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
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
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	return ctxFiber.Status(fiber.StatusOK).JSON(accessToken)
}

func (a *ApplicationAdapter) VerifyJWT(ctxFiber *fiber.Ctx) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.UserContext(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "applicationAdapter.verifyJWT", trace.SpanKindInternal)
	defer span.End()
	logger.Info(ctx, "VerifyJWT called")

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
	if err := ctxFiber.BodyParser(&verifyJWTReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
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
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	resp := external.VerifyJWTResponse{
		Response: "JWT verification successful",
		Claims:   claims,
	}

	return ctxFiber.Status(fiber.StatusOK).JSON(resp)
}

func (a *ApplicationAdapter) WellKnownJwksGet(ctxFiber *fiber.Ctx) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.UserContext(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "applicationAdapter.wellKnownJwksGet", trace.SpanKindInternal)
	defer span.End()
	logger.Info(ctx, "WellKnownJwksGet called")

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
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	return ctxFiber.Status(fiber.StatusOK).JSON(jwks)
}

func (a *ApplicationAdapter) RefreshToken(ctxFiber *fiber.Ctx) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.UserContext(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "applicationAdapter.refreshToken", trace.SpanKindInternal)
	defer span.End()
	logger.Info(ctx, "RefreshToken called")

	logger.Debug(
		ctx,
		a.cfg.App.Name,
		zap.ByteString("headers", utils.FormatHeadersAsJSON(ctxFiber.GetReqHeaders())),
		zap.String("host", ctxFiber.Hostname()),
		zap.String("path", ctxFiber.Path()),
		zap.ByteString("query", ctxFiber.Request().URI().QueryString()),
	)

	verifyJWTReq := external.VerifyJWTRequest{}
	if err := ctxFiber.BodyParser(&verifyJWTReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
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
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	return ctxFiber.Status(fiber.StatusOK).JSON(tokenRefreshed)
}

// VerifyES256JWT handles the verification of ES256 JWT tokens.
func (a *ApplicationAdapter) VerifyES256JWT(ctxFiber *fiber.Ctx) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctxFiber.UserContext(), a.cfg.HTTP.Timeout)
	defer cancel()

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctxWithTimeout, "applicationAdapter.verifyES256JWT", trace.SpanKindInternal)
	defer span.End()
	logger.Info(ctx, "VerifyES256JWT called")

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
	if err := ctxFiber.BodyParser(&verifyJWTReq); err != nil {
		logger.Error(ctx, "failed to parse request body", zap.Error(err))
		errorResponse := external.NewResponseError(ctx,
			fiber.StatusBadRequest,
			fiber.ErrBadRequest,
			fiber.ErrBadRequest.Message,
			"failed to parse request body",
			err.Error(),
			external.BUSSINESS_ERROR)
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
		return ctxFiber.Status(errorResponse.StatusCode).JSON(errorResponse)
	}

	return ctxFiber.Status(fiber.StatusOK).JSON(claims)
}