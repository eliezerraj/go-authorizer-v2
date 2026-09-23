package usecase

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/go-authorizer-v2/application/infrastructure/repository"
	"github.com/go-authorizer-v2/application/domain/entity"

	"github.com/eliezerraj/go-core/v3/logger"
	"github.com/golang-jwt/jwt/v5"
)

type ApiKeyUseCase struct {
	ies256KeyRepository repository.IES256KeyRepository
}

type IApiKeyUseCase interface {
	VerifyJwtES256(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error)
}

func NewApiKeyUseCase(ies256KeyRepository repository.IES256KeyRepository) *ApiKeyUseCase {
	logger.InfoOutCtx("Creating new API key use case instance SUCCESSFULLY")

	return &ApiKeyUseCase{
		ies256KeyRepository: ies256KeyRepository,
	}
}

func (uc *ApiKeyUseCase) VerifyJwtES256(ctx context.Context, tokenString string) (*entity.AccessTokenClaims, error) {
	logger.InfoOutCtx("Verifying JWT with ES256", zap.String("token", tokenString))

	if tokenString == "" {
		logger.ErrorOutCtx("Token string is empty")
		return nil, fmt.Errorf("token string is empty")
	}

	publicKey, err := uc.ies256KeyRepository.GetActivePublicKey(ctx)
	if err != nil {
		logger.ErrorOutCtx("Failed to retrieve public key: %v", zap.Error(err))
		return nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &entity.TokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok || token.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		logger.ErrorOutCtx("Failed to parse token: %v", zap.Error(err))
		return nil, err
	}

	if !token.Valid {
		logger.ErrorOutCtx("Token is invalid")
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*entity.TokenCustomClaims)
	if !ok {
		logger.ErrorOutCtx("Failed to cast token claims")
		return nil, fmt.Errorf("failed to cast token claims")
	}

	return &entity.AccessTokenClaims{
        Issuer:    claims.Issuer,
        Subject:   claims.Subject,
        Audience:  claims.Audience,
        IssuedAt:  claims.IssuedAt.Time,
        NotBefore: claims.NotBefore.Time,
        ExpiresAt: claims.ExpiresAt.Time,
        JWTID:     claims.ID,
	}, nil
}