package controller

import (
	"context"

	"go.uber.org/zap"

	"github.com/eliezerraj/go-core/v3/logger"

	"github.com/go-authorizer-v2/application/domain/usecase"
	"github.com/go-authorizer-v2/application/domain/external"
	"github.com/go-authorizer-v2/application/domain/entity"
	"github.com/go-authorizer-v2/application/tracing"
	"github.com/go-authorizer-v2/application/controller/validator"

	"go.opentelemetry.io/otel/trace"
)

type AuthorizerController struct {
	schema validator.Schema
	loginUseCase usecase.ILoginUseCase
}

// NewAuthorizerController creates a new instance of AuthorizerController with the provided login use case.
func NewAuthorizerController(loginUseCase usecase.ILoginUseCase) *AuthorizerController {
	logger.InfoOutCtx("initializing authorizer controller SUCCESSFULLY")

	schema := validator.Schema{
			Validate: func(ctx context.Context, data any) error {
				return nil
			},
		}

	return &AuthorizerController{
		schema:       schema,
		loginUseCase: loginUseCase,
	}
}

func (p *AuthorizerController) Login(ctx context.Context, req external.LoginRequest) (*entity.OAuthToken, error) {
	logger.Info(ctx, "authorizer controller Login called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "authorizerController.login", trace.SpanKindInternal)
	defer span.End()

	login := entity.Login{
		ClientID: req.ClientID,
		SecretID: req.SecretID,
	}

	// Call the use case to perform login
	res, err := p.loginUseCase.Login(ctx, login)
	if err != nil {
		logger.Error(ctx, "authorizer controller Login failed", zap.Error(err))
		return nil, err
	}

	return res, nil
}

func (p *AuthorizerController) VerifyJWT(ctx context.Context, req external.VerifyJWTRequest) (*entity.AccessTokenClaims, error) {
	logger.Info(ctx, "authorizer controller VerifyJWT called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "authorizerController.verifyJWT", trace.SpanKindInternal)
	defer span.End()

	return p.loginUseCase.VerifyJWT(ctx, req.Token)
}

func (p *AuthorizerController) WellKnownJwksGet(ctx context.Context) (*entity.WellKnownJwks, error) {
	logger.Info(ctx, "authorizer controller WellKnownJwks called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "authorizerController.WellKnownJwksGet", trace.SpanKindInternal)
	defer span.End()

	return p.loginUseCase.WellKnownJwksGet(ctx)
}