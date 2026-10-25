package usecase

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/eliezerraj/go-core/v3/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/go-authorizer-v2/application/domain/entity"
	"github.com/go-authorizer-v2/application/infrastructure/module"
	"github.com/go-authorizer-v2/application/infrastructure/repository"
	"github.com/go-authorizer-v2/application/infrastructure/security"
	"github.com/go-authorizer-v2/application/tracing"

	"go.opentelemetry.io/otel/trace"
)

type AuthUseCase struct {
    keyRepository 	repository.IKeyRepository
    tokenService 	security.ITokenService	
	tokenTTL     	time.Duration
	issuer      	string
	authModule 		module.AuthModule
}

type IAuthUseCase interface {
	Login(ctx context.Context, login entity.Login) (*entity.OAuthToken, error)
	VerifyJWT(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error)
	WellKnownJwksGet(ctx context.Context) (*entity.WellKnownJwks, error)
	RefreshToken(ctx context.Context, tokenString string) (*entity.OAuthToken, error)

	ClientCredentials(ctx context.Context, req entity.ClientCredential) (*entity.OAuthToken, error)
	PrivateKeyJwt(ctx context.Context, req entity.ClientCredential) (*entity.OAuthToken, error)
}

func NewAuthUseCase(tokenTTL time.Duration, keyRepository repository.IKeyRepository, tokenService security.ITokenService, issuer string, authModule module.AuthModule) IAuthUseCase {
	logger.Info(context.Background(), "initializing auth usecase SUCCESSFULLY")
	
	return &AuthUseCase{
		keyRepository: 	keyRepository,
		tokenService: 	tokenService,
		tokenTTL: tokenTTL,
		issuer:   issuer,
		authModule: authModule,
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

	// Extract the client assertion from the request if needed.
	clientAssertion := clientCredential.ClientAssertion
	if clientAssertion == "" {
		logger.Error(ctx, "client assertion is missing")
		return nil, fmt.Errorf("client assertion is missing")
	}

	unverifiedClaims := &jwt.RegisteredClaims{}
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(clientAssertion, unverifiedClaims)
	if err != nil {
		logger.Error(ctx, "failed to parse client assertion", zap.Error(err))
		return nil, fmt.Errorf("invalid client assertion: %w", err)
	}

	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("client assertion has an invalid kid")
	}

	metadataURL, err := validateMetadataURL(unverifiedClaims.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid client metadata URL: %w", err)
	}

	// Retrieve client metadata from the provided metadata URL.
	metadata, err := uc.authModule.GetClientMetadata(ctx, metadataURL)
	if err != nil {
		logger.Error(ctx, "failed to retrieve client metadata", zap.Error(err))
		return nil, err
	}

	// Check ClientID vs client assertion issuer.
	fmt.Printf("======================Validating Client metadata: %+v Issuer: %s\n", metadata.ClientID , unverifiedClaims.Issuer)
	if metadata.ClientID != unverifiedClaims.Issuer {
		return nil, fmt.Errorf("client metadata client_id does not match client assertion issuer")
	}

	jwksURL, err := validateMetadataURL(metadata.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("invalid client JWKS URL: %w", err)
	}

	// POST request to retrieve JWKS from the client's JWKS URL.
	resJWKS, err := uc.authModule.GetJwks(ctx, jwksURL)
	if err != nil {
		logger.Error(ctx, "failed to retrieve client JWKS", zap.Error(err))
		return nil, err
	}

	// Get the KEYS from the JWKS response and find the matching signing key for the client assertion.
	var signingKey *ecdsa.PublicKey
	for _, jwk := range resJWKS.Keys {
		if jwk.KeyID != kid || jwk.KeyType != "EC" || jwk.Crv != "P-256" || jwk.Algorithm != "ES256" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}

		xBytes, xErr := base64.RawURLEncoding.DecodeString(jwk.X)
		yBytes, yErr := base64.RawURLEncoding.DecodeString(jwk.Y)
		if xErr != nil || yErr != nil || len(xBytes) != 32 || len(yBytes) != 32 {
			return nil, fmt.Errorf("client JWKS contains invalid EC coordinates for kid %q", kid)
		}
		x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, fmt.Errorf("client JWKS contains invalid P-256 public key for kid %q", kid)
		}
		signingKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		break
	}
	if signingKey == nil {
		return nil, fmt.Errorf("no matching ES256 signing key found for kid %q", kid)
	}

	verifiedClaims := &jwt.RegisteredClaims{}
	verifiedToken, err := jwt.ParseWithClaims(clientAssertion, verifiedClaims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodES256 || token.Header["kid"] != kid {
			return nil, fmt.Errorf("unexpected client assertion signing method or kid")
		}
		return signingKey, nil
	}, jwt.WithIssuedAt())
	if err != nil {
		logger.Error(ctx, "failed to verify client assertion", zap.Error(err))
		return nil, fmt.Errorf("invalid client assertion: %w", err)
	}
	if !verifiedToken.Valid {
		return nil, fmt.Errorf("invalid client assertion")
	}

	// Issue a new access token using the verified client assertion and the active private key.
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
        Subject:   verifiedClaims.Issuer,
        ClientID:  verifiedClaims.Issuer,
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

func validateMetadataURL(rawURL string) (string, error) {
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", err
	}
	if (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return "", fmt.Errorf("URL must be an absolute HTTP(S) URL without user info or fragment")
	}
	return parsedURL.String(), nil
}