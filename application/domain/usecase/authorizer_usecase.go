package usecase

import (
	"time"
	"context"
	
	"github.com/google/uuid"
	
	"go.uber.org/zap"
	"github.com/eliezerraj/go-core/v3/logger"

	"github.com/go-authorizer-v2/application/tracing"
    "github.com/go-authorizer-v2/application/domain/entity"
    "github.com/go-authorizer-v2/application/infrastructure/repository"
    "github.com/go-authorizer-v2/application/infrastructure/security"

	"go.opentelemetry.io/otel/trace"
)

const (
	DefaultIssuer   = "go-authorizer-v2"
	DefaultAudience = "aud-teste"
)

type LoginUseCase struct {
    keyRepository 	repository.IKeyRepository
    tokenService 	security.ITokenService	
	tokenTTL     	time.Duration
}

type ILoginUseCase interface {
	Login(ctx context.Context, login entity.Login) (*entity.OAuthToken, error)
	VerifyJWT(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error)
	WellKnownJwksGet(ctx context.Context) (*entity.WellKnownJwks, error)
	RefreshToken(ctx context.Context, tokenString string) (*entity.OAuthToken, error)
}

func NewLoginUseCase(tokenTTL time.Duration, keyRepository repository.IKeyRepository, tokenService security.ITokenService) ILoginUseCase {
	logger.InfoOutCtx("initializing login usecase SUCCESSFULLY")
	
	return &LoginUseCase{
		keyRepository: 	keyRepository,
		tokenService: 	tokenService,
		tokenTTL: tokenTTL,
	}
}

// Login handles the login use case, generating an OAuth token for the given login credentials.
func (uc *LoginUseCase) Login(ctx context.Context, login entity.Login) (*entity.OAuthToken, error) {
	logger.Info(ctx, "login usecase Login called ")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "loginUsecase.Login", trace.SpanKindInternal)
	defer span.End()

	client := entity.Client{
		ID: login.ClientID,
	}

    privKey, kid, err := uc.keyRepository.GetActivePrivateKey(ctx)
    if err != nil {
		logger.ErrorOutCtx("error getting active private key", zap.Any("error", err))
        return nil, err
    }

	var scope = "teste:read"
	var issuer = DefaultIssuer
	var audience []string = []string{DefaultAudience}

	now := time.Now()
    claims := entity.AccessTokenClaims{
        Issuer:    issuer,
        Subject:   client.ID,
        ClientID:  client.ID,
        Audience:  audience,
        Scope:     scope,
        IssuedAt:  now,
        NotBefore: now,
        ExpiresAt: now.Add(uc.tokenTTL),
        JWTID:     uuid.NewString(),
    }

	tokenString, err := uc.tokenService.SignJWT(ctx, claims, privKey, kid)
    if err != nil {
		logger.ErrorOutCtx("error signing JWT", zap.Any("error", err))
        return nil, err
    }

	return &entity.OAuthToken{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int(uc.tokenTTL.Seconds()),
		RefreshToken: "",
		Scope:        scope,
	}, nil
}

// VerifyJWT handles the verification of a JWT, returning the claims if the token is valid.
func (uc *LoginUseCase) VerifyJWT(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error) {
	logger.Info(ctx, "login usecase VerifyJWT called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "loginUsecase.VerifyJWT", trace.SpanKindInternal)
	defer span.End()

	pubKey, err := uc.keyRepository.GetActivePublicKey(ctx)
	if err != nil {
		logger.ErrorOutCtx("error getting active public key", zap.Any("error", err))
		return nil, err
	}

	return uc.tokenService.VerifyJWT(ctx, tokenString, pubKey)
}

// WellKnownJwksGet handles the retrieval of the well-known JWKS (JSON Web Key Set) for the authorization server.
func (uc *LoginUseCase) WellKnownJwksGet(ctx context.Context) (*entity.WellKnownJwks, error) {
	logger.Info(ctx, "login usecase WellKnownJwksGet called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "loginUsecase.WellKnownJwksGet", trace.SpanKindInternal)
	defer span.End()

	jwk, err := uc.keyRepository.GetAllPublicKeys(ctx)
	if err != nil {
		logger.ErrorOutCtx("error getting active public key", zap.Any("error", err))
		return nil, err
	}
	
	return &entity.WellKnownJwks{
		Keys: jwk,
	}, nil
}

// RefreshToken handles the refresh token use case, generating a new OAuth token for the given refresh token.
func (uc *LoginUseCase) RefreshToken(ctx context.Context, tokenString string) (*entity.OAuthToken, error) {
	logger.Info(ctx, "login usecase RefreshToken called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "loginUsecase.RefreshToken", trace.SpanKindInternal)
	defer span.End()

	pubKey, err := uc.keyRepository.GetActivePublicKey(ctx)
	if err != nil {
		logger.ErrorOutCtx("error getting active public key", zap.Any("error", err))
		return nil, err
	}

	claims, err := uc.tokenService.VerifyJWT(ctx, tokenString, pubKey)
	if err != nil {
		logger.ErrorOutCtx("error verifying JWT", zap.Any("error", err))
		return nil, err
	}

	privKey, kid, err := uc.keyRepository.GetActivePrivateKey(ctx)
    if err != nil {
        logger.ErrorOutCtx("error getting active private key", zap.Any("error", err))
        return nil, err
    }
	
	now := time.Now()
    claims.IssuedAt = now
    claims.NotBefore = now
    claims.ExpiresAt = now.Add(uc.tokenTTL)
    claims.JWTID = uuid.NewString()

	tokenRefreshed, err := uc.tokenService.SignJWT(ctx, *claims, privKey, kid)
	if err != nil {
		logger.ErrorOutCtx("error signing JWT", zap.Any("error", err))
		return nil, err
	}
	
	return &entity.OAuthToken{
		AccessToken:  tokenRefreshed,
		TokenType:    "Bearer",
		ExpiresIn:    int(uc.tokenTTL.Seconds()),
	}, nil
}