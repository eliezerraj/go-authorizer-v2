package repository

import (
    "context"
    "crypto/rsa"
    "os"

    "github.com/eliezerraj/go-core/v3/logger"
    "go.uber.org/zap"

    "github.com/golang-jwt/jwt/v5"
    "github.com/go-authorizer-v2/application/domain/entity"
    "github.com/go-authorizer-v2/application/infrastructure/security"
)

type KeyRepository struct {
    PrivateKey *rsa.PrivateKey
    PublicKey  *rsa.PublicKey
    Kid        string
}

type IKeyRepository interface {
    GetActivePrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error) // Returns (Key, KeyID/kid, error)
    GetActivePublicKey(ctx context.Context) (*rsa.PublicKey, error)
    GetAllPublicKeys(ctx context.Context) ([]entity.JWK, error)
}

// NewKeyRepository load the RSA private and public keys from the given PEM file paths and initializes a new KeyRepository.
func NewKeyRepository(privateKeyPEMPath, publicKeyPEMPath, kid string) (*KeyRepository, error) {
    logger.InfoOutCtx("initializing NewKeyRepository SUCCESSFULLY")

    pemBytes, err := os.ReadFile(privateKeyPEMPath)
    if err != nil {
        logger.ErrorOutCtx("error reading private key PEM file", zap.Any("error", err))
        return nil, err
    }
    privKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
    if err != nil {
        logger.ErrorOutCtx("error parsing RSA private key from PEM", zap.Any("error", err))
        return nil, err
    }

    pemBytes, err = os.ReadFile(publicKeyPEMPath)
    if err != nil {
        logger.ErrorOutCtx("error reading public key PEM file", zap.Any("error", err))
        return nil, err
    }
    pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes)
    if err != nil {
        logger.ErrorOutCtx("error parsing RSA public key from PEM", zap.Any("error", err))
        return nil, err
    }

    return &KeyRepository{
        PrivateKey: privKey,
        PublicKey:  pubKey,
        Kid:        kid,
    }, nil
}

// GetActivePrivateKey returns the active private key along with its key ID (kid).
func (r *KeyRepository) GetActivePrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
    return r.PrivateKey, r.Kid, nil
}

func (r *KeyRepository) GetActivePublicKey(ctx context.Context) (*rsa.PublicKey, error) {
    return r.PublicKey, nil
}

// GetAllPublicKeys returns all public keys in JWK format.
func (r *KeyRepository) GetAllPublicKeys(ctx context.Context) ([]entity.JWK, error) {
    jwk := security.RSAPublicKeyToJWK(r.PublicKey, r.Kid)
    return []entity.JWK{jwk}, nil
}
