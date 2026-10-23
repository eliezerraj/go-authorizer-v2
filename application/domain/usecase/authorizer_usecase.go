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

type AuthUseCase struct {
    keyRepository 	repository.IKeyRepository
    tokenService 	security.ITokenService	
	tokenTTL     	time.Duration
	issuer      	string
}

type IAuthUseCase interface {
	Login(ctx context.Context, login entity.Login) (*entity.OAuthToken, error)
	VerifyJWT(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error)
	WellKnownJwksGet(ctx context.Context) (*entity.WellKnownJwks, error)
	RefreshToken(ctx context.Context, tokenString string) (*entity.OAuthToken, error)

	ClientCredentials(ctx context.Context, req entity.ClientCredential) (*entity.OAuthToken, error)
}

func NewAuthUseCase(tokenTTL time.Duration, keyRepository repository.IKeyRepository, tokenService security.ITokenService, issuer string) IAuthUseCase {
	logger.Info(context.Background(), "initializing auth usecase SUCCESSFULLY")
	
	return &AuthUseCase{
		keyRepository: 	keyRepository,
		tokenService: 	tokenService,
		tokenTTL: tokenTTL,
		issuer:   issuer,
	}
}

// Login handles the login use case, generating an OAuth token for the given login credentials.
func (uc *AuthUseCase) Login(ctx context.Context, login entity.Login) (*entity.OAuthToken, error) {
	logger.Info(ctx, "Login called ")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "usecase.login", trace.SpanKindInternal)
	defer span.End()

	client := entity.Client{
		ID: login.ClientID,
	}

    privKey, kid, err := uc.keyRepository.GetActivePrivateKey(ctx)
    if err != nil {
		logger.Error(ctx, "error getting active private key", zap.Any("error", err))
        return nil, err
    }

	var scope = "inventory:read inventory:create inventory:update order:read order:create order:history checkout:read checkout:create payment:read payment:create statistics:compute inventory_a2a:monitor inventory_a2a:manage"

	now := time.Now()
    claims := entity.AccessTokenClaims{
        Issuer:    uc.issuer,
        Subject:   client.ID,
        ClientID:  client.ID,
        Audience:  []string{client.ID},
        Scope:     scope,
        IssuedAt:  now,
        NotBefore: now,
        ExpiresAt: now.Add(uc.tokenTTL),
        JWTID:     uuid.NewString(),
    }

	tokenString, err := uc.tokenService.SignJWT(ctx, claims, privKey, kid)
    if err != nil {
		logger.Error(ctx, "error signing JWT", zap.Any("error", err))
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
func (uc *AuthUseCase) VerifyJWT(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error) {
	logger.Info(ctx, "VerifyJWT called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "usecase.verifyJWT", trace.SpanKindInternal)
	defer span.End()

	pubKey, err := uc.keyRepository.GetActivePublicKey(ctx)
	if err != nil {
		logger.Error(ctx, "error getting active public key", zap.Any("error", err))
		return nil, err
	}

	return uc.tokenService.VerifyJWT(ctx, tokenString, pubKey)
}

// WellKnownJwksGet handles the retrieval of the well-known JWKS (JSON Web Key Set) for the authorization server.
func (uc *AuthUseCase) WellKnownJwksGet(ctx context.Context) (*entity.WellKnownJwks, error) {
	logger.Info(ctx, "WellKnownJwksGet called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "usecase.wellKnownJwksGet", trace.SpanKindInternal)
	defer span.End()

	jwk, err := uc.keyRepository.GetAllPublicKeys(ctx)
	if err != nil {
		logger.Error(ctx, "error getting active public key", zap.Any("error", err))
		return nil, err
	}
	
	return &entity.WellKnownJwks{
		Keys: jwk,
	}, nil
}

// RefreshToken handles the refresh token use case, generating a new OAuth token for the given refresh token.
func (uc *AuthUseCase) RefreshToken(ctx context.Context, tokenString string) (*entity.OAuthToken, error) {
	logger.Info(ctx, "RefreshToken called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "usecase.refreshToken", trace.SpanKindInternal)
	defer span.End()

	pubKey, err := uc.keyRepository.GetActivePublicKey(ctx)
	if err != nil {
		logger.Error(ctx, "error getting active public key", zap.Any("error", err))
		return nil, err
	}

	claims, err := uc.tokenService.VerifyJWT(ctx, tokenString, pubKey)
	if err != nil {
		logger.Error(ctx, "error verifying JWT", zap.Any("error", err))
		return nil, err
	}

	privKey, kid, err := uc.keyRepository.GetActivePrivateKey(ctx)
    if err != nil {
        logger.Error(ctx, "error getting active private key", zap.Any("error", err))
        return nil, err
    }
	
	now := time.Now()
    claims.IssuedAt = now
    claims.NotBefore = now
    claims.ExpiresAt = now.Add(uc.tokenTTL)
    claims.JWTID = uuid.NewString()

	tokenRefreshed, err := uc.tokenService.SignJWT(ctx, *claims, privKey, kid)
	if err != nil {
		logger.Error(ctx, "error signing JWT", zap.Any("error", err))
		return nil, err
	}
	
	return &entity.OAuthToken{
		AccessToken:  tokenRefreshed,
		TokenType:    "Bearer",
		ExpiresIn:    int(uc.tokenTTL.Seconds()),
	}, nil
}

// ClientCredentials handles the client credentials grant type use case, generating an OAuth token based on the provided request.
func (uc *AuthUseCase) ClientCredentials(ctx context.Context, clientCredential entity.ClientCredential) (*entity.OAuthToken, error) {
	logger.Info(ctx, "ClientCredentials called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "usecase.clientCredentials", trace.SpanKindInternal)
	defer span.End()

    privKey, kid, err := uc.keyRepository.GetActivePrivateKey(ctx)
    if err != nil {
		logger.Error(ctx, "error getting active private key", zap.Any("error", err))
        return nil, err
    }

	var scope = ""
	var role = "order-admin-role order-all-role order-resource-role order-tool-role"

	now := time.Now()
    claims := entity.AccessTokenClaims{
        Issuer:    uc.issuer,
        Subject:   clientCredential.ClientID,
        ClientID:  clientCredential.ClientID,
        Audience:  []string{clientCredential.Resource},
        Scope:     scope,
        Role:      role,
        IssuedAt:  now,
        NotBefore: now,
        ExpiresAt: now.Add(uc.tokenTTL),
        JWTID:     uuid.NewString(),
    }

	tokenString, err := uc.tokenService.SignJWT(ctx, claims, privKey, kid)
    if err != nil {
		logger.Error(ctx, "error signing JWT", zap.Any("error", err))
        return nil, err
    }

	return &entity.OAuthToken{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int(uc.tokenTTL.Seconds()),
		RefreshToken: "",
		Scope:        scope,
		Role:        role,
	}, nil
}

// ClientCredentials handles the client credentials grant type use case, generating an OAuth token based on the provided request.
func (uc *AuthUseCase) PrivateKeyJwt(ctx context.Context, clientCredential entity.ClientCredential) (*entity.OAuthToken, error) {
	logger.Info(ctx, "PrivateKeyJwt called")

	// Tracer for OpenTelemetry
	ctx, span := tracing.CustomStartSpanCtx(ctx, "usecase.privateKeyJwt", trace.SpanKindInternal)
	defer span.End()

    privKey, kid, err := uc.keyRepository.GetActivePrivateKey(ctx)
    if err != nil {
		logger.Error(ctx, "error getting active private key", zap.Any("error", err))
        return nil, err
    }

	var scope = ""
	var role = "order-admin-role order-all-role order-resource-role order-tool-role"

	now := time.Now()
    claims := entity.AccessTokenClaims{
        Issuer:    uc.issuer,
        Subject:   clientCredential.ClientID,
        ClientID:  clientCredential.ClientID,
        Audience:  []string{clientCredential.Resource},
        Scope:     scope,
        Role:      role,
        IssuedAt:  now,
        NotBefore: now,
        ExpiresAt: now.Add(uc.tokenTTL),
        JWTID:     uuid.NewString(),
    }

	tokenString, err := uc.tokenService.SignJWT(ctx, claims, privKey, kid)
    if err != nil {
		logger.Error(ctx, "error signing JWT", zap.Any("error", err))
        return nil, err
    }

	return &entity.OAuthToken{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int(uc.tokenTTL.Seconds()),
		RefreshToken: "",
		Scope:        scope,
		Role:        role,
	}, nil
}