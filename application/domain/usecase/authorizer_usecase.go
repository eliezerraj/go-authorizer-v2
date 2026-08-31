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

type LoginUseCase struct {
    keyRepository 	repository.IKeyRepository
    tokenService 	security.ITokenService	
	tokenTTL     	time.Duration
}

type ILoginUseCase interface {
	Login(ctx context.Context, login entity.Login) (*entity.OAuthToken, error)
	VerifyJWT(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error)
}

func NewLoginUseCase(tokenTTL time.Duration, keyRepository repository.IKeyRepository, tokenService security.ITokenService) ILoginUseCase {
	logger.InfoOutCtx("initializing login usecase SUCCESSFULLY")
	
	return &LoginUseCase{
		keyRepository: 	keyRepository,
		tokenService: 	tokenService,
		tokenTTL: tokenTTL,
	}
}

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
	var issuer = "go-authorizer-v2"
	var audience []string = []string{"aud-teste"}

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