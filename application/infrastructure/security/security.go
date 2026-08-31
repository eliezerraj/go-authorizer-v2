package security

import (
    "context"
    "crypto/rsa"
    "encoding/base64"
    "math/big"
    "errors"
    "fmt"

    "go.uber.org/zap"
    "github.com/eliezerraj/go-core/v3/logger"

    "github.com/golang-jwt/jwt/v5"

    "github.com/go-authorizer-v2/application/domain/entity"
)

type TokenService struct{}

type ITokenService interface {
    SignJWT(ctx context.Context, claims entity.AccessTokenClaims, privateKey *rsa.PrivateKey, kid string) (string, error)
    VerifyJWT(ctx context.Context, tokenString string, publicKey *rsa.PublicKey) (*entity.AccessTokenClaims, error)
}

func NewTokenService() ITokenService {
    logger.InfoOutCtx("initializing JWTTokenService SUCCESSFULLY")
    
    return &TokenService{}
}

func RSAPublicKeyToJWK(pub *rsa.PublicKey, kid string) entity.JWK {
    nBytes := pub.N.Bytes()
    eBytes := big.NewInt(int64(pub.E)).Bytes()

    return entity.JWK{
        KeyID:     kid,
        KeyType:   "RSA",
        Algorithm: "RS256",
        Use:       "sig",
        N:         base64.RawURLEncoding.EncodeToString(nBytes),
        E:         base64.RawURLEncoding.EncodeToString(eBytes),
    }
}

func (s *TokenService) SignJWT(ctx context.Context, claims entity.AccessTokenClaims,  privateKey *rsa.PrivateKey,  kid string) (string, error) {
    logger.InfoOutCtx("signing JWT with provided claims")

    if privateKey == nil {
        logger.ErrorOutCtx("private key is nil")
        return "", errors.New("private key cannot be nil")
    }

    // 1. Map domain claims to JWT registered + custom claims
    jwtClaims := entity.TokenCustomClaims{
        ClientID: claims.ClientID,
        Scope:    claims.Scope,
        Cnf:      claims.Cnf,
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    claims.Issuer,
            Subject:   claims.Subject,
            Audience:  jwt.ClaimStrings(claims.Audience),
            ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
            IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
            NotBefore: jwt.NewNumericDate(claims.NotBefore),
            ID:        claims.JWTID,
        },
    }

    // 2. Create token with RS256 signing method
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)

    // 3. Set the Key ID (kid) in header for JWKS lookup & key rotation
    if kid != "" {
        token.Header["kid"] = kid
    }

    // 4. Sign the token with RSA private key
    tokenString, err := token.SignedString(privateKey)
    if err != nil {
        logger.ErrorOutCtx("failed to sign JWT", zap.Error(err))
        return "", fmt.Errorf("failed to sign JWT: %w", err)
    }

    return tokenString, nil
}

func (s *TokenService) VerifyJWT(ctx context.Context, tokenString string, publicKey *rsa.PublicKey) (*entity.AccessTokenClaims, error) {
    logger.InfoOutCtx("verifying JWT with provided token string")

    if publicKey == nil {
        logger.ErrorOutCtx("public key is nil")
        return nil, errors.New("public key cannot be nil")
    }

    token, err := jwt.ParseWithClaims(tokenString, &entity.TokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return publicKey, nil
    })
    if err != nil {
        logger.ErrorOutCtx("failed to parse JWT", zap.Error(err))
        return nil, fmt.Errorf("failed to parse JWT: %w", err)
    }

    claims, ok := token.Claims.(*entity.TokenCustomClaims)
    if !ok || !token.Valid {
        logger.ErrorOutCtx("invalid JWT claims")
        return nil, errors.New("invalid JWT claims")
    }

    return &entity.AccessTokenClaims{
        Issuer:    claims.Issuer,
        Subject:   claims.Subject,
        ClientID:  claims.ClientID,
        Audience:  claims.Audience,
        Scope:     claims.Scope,
        IssuedAt:  claims.IssuedAt.Time,
        NotBefore: claims.NotBefore.Time,
        ExpiresAt: claims.ExpiresAt.Time,
        JWTID:     claims.ID,
        Cnf:       claims.Cnf,
    }, nil
}