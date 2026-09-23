package repository

import (
    "context"
    "crypto/ecdsa"
    "os"

    "github.com/eliezerraj/go-core/v3/logger"
    "go.uber.org/zap"

    "github.com/golang-jwt/jwt/v5"
)

type EC256KeyRepository struct {
    PublicKey *ecdsa.PublicKey
    Kid       string
}

type IES256KeyRepository interface {
    GetActivePublicKey(ctx context.Context) (*ecdsa.PublicKey, error)
}

// NewEC256KeyRepository load the EC256 public key from the given PEM file path and initializes a new EC256KeyRepository.
func NewEC256KeyRepository(publicKeyPEMPath, kid string) (*EC256KeyRepository, error) {
    logger.InfoOutCtx("initializing NewEC256KeyRepository SUCCESSFULLY")

    pemBytes, err := os.ReadFile(publicKeyPEMPath)
    if err != nil {
        logger.ErrorOutCtx("error reading public key PEM file", zap.Any("error", err))
        return nil, err
    }
    pubKey, err := jwt.ParseECPublicKeyFromPEM(pemBytes)
    if err != nil {
        logger.ErrorOutCtx("error parsing ES256 public key from PEM", zap.Any("error", err))
        return nil, err
    }

    return &EC256KeyRepository{
        PublicKey: pubKey,
        Kid:       kid,
    }, nil
}

func (r *EC256KeyRepository) GetActivePublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
    return r.PublicKey, nil
}
