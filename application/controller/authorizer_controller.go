package controller

import (
	"context"
	"errors"

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
	authUseCase usecase.IAuthUseCase
	apiKeyUseCase usecase.IApiKeyUseCase
}

// NewAuthorizerController creates a new instance of AuthorizerController with the provided login use case.
func NewAuthorizerController(authUseCase usecase.IAuthUseCase, apiKeyUseCase usecase.IApiKeyUseCase) *AuthorizerController {
	logger.Info(context.Background(), "initializing authorizer controller SUCCESSFULLY")

	schema := validator.Schema{
			Validate: func(ctx context.Context, data any) error {
				return nil
			},
		}

	return &AuthorizerController{
		schema:       schema,
		authUseCase: authUseCase,
		apiKeyUseCase: apiKeyUseCase,
	}
}

func (p *AuthorizerController) Login(ctx context.Context, req external.LoginRequest) (*entity.OAuthToken, error) {
	logger.Info(ctx, "authorizer controller Login called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "controller.login", trace.SpanKindInternal)
	defer span.End()

	login := entity.Login{
		ClientID: req.ClientID,
		SecretID: req.SecretID,
	}

	// Call the use case to perform login
	res, err := p.authUseCase.Login(ctx, login)
	if err != nil {
		logger.Error(ctx, "authorizer controller Login failed", zap.Error(err))
		return nil, err
	}

	return res, nil
}

func (p *AuthorizerController) VerifyJWT(ctx context.Context, req external.VerifyJWTRequest) (*entity.AccessTokenClaims, error) {
	logger.Info(ctx, "VerifyJWT called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "controller.verifyJWT", trace.SpanKindInternal)
	defer span.End()

	return p.authUseCase.VerifyJWT(ctx, req.Token)
}

func (p *AuthorizerController) WellKnownJwksGet(ctx context.Context) (*entity.WellKnownJwks, error) {
	logger.Info(ctx, "WellKnownJwks called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "controller.wellKnownJwksGet", trace.SpanKindInternal)
	defer span.End()

	return p.authUseCase.WellKnownJwksGet(ctx)
}

func (p *AuthorizerController) RefreshToken(ctx context.Context, req external.VerifyJWTRequest) (*entity.OAuthToken, error) {
	logger.Info(ctx, "RefreshToken called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "controller.refreshToken", trace.SpanKindInternal)
	defer span.End()

	return p.authUseCase.RefreshToken(ctx, req.Token)
}

func (p *AuthorizerController) VerifyES256JWT(ctx context.Context, req external.VerifyJWTRequest) (*entity.AccessTokenClaims, error) {
	logger.Info(ctx, "VerifyES256JWT called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "controller.verifyES256JWT", trace.SpanKindInternal)
	defer span.End()

	return p.apiKeyUseCase.VerifyJwtES256(ctx, req.Token)
}

// GrantType handles different OAuth2 grant types based on the request.
func (p *AuthorizerController) GrantType(ctx context.Context, req external.AuthTokenRequest) (*entity.OAuthToken, error) {
	logger.Info(ctx, "GrantType called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "controller.grantType:"+req.GrantType, trace.SpanKindInternal)
	defer span.End()

	clientCredential := entity.ClientCredential{
		ClientID:  req.ClientID,
		SecretID:  req.SecretID,
		Resource:  req.Resource,
		GrantType: req.GrantType,
	}

	switch req.GrantType {
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		//handleTokenExchange()

	case "authorization_code":
		//handleAuthorizationCode()

	case "client_credentials":

		res, err := p.authUseCase.ClientCredentials(ctx, clientCredential)
		if err != nil {
			logger.Error(ctx, "authorizer controller ClientCredentials failed", zap.Error(err))
			return nil, err
		}
		return res, nil
	default:
		return nil, errors.New("unsupported grant_type")
	}

	return nil, nil
}