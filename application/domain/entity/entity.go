package entity

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ClientCredential struct {
	ClientID            string `json:"client_id,omitempty"`
	SecretID            string `json:"secret_id,omitempty"`
    Resource            string `json:"resource,omitempty"`
    GrantType           string `json:"grant_type,omitempty"`
    ClientAssertion     string `json:"client_assertion,omitempty"`
    ClientAssertionType string `json:"client_assertion_type,omitempty"`
}

type Login struct {
	ClientID string `json:"client_id,omitempty"`
	SecretID string `json:"secret_id,omitempty"`
}

type Client struct {
	ID       string `json:"id,omitempty"`
    Name     string   `json:"name,omitempty"`
	Audience []string `json:"audience,omitempty"`
}

type TokenCustomClaims struct {
    ClientID string         `json:"client_id,omitempty"`
    Scope    string        `json:"scope,omitempty"`
    Role     string        `json:"role,omitempty"`
    Cnf      *Confirmation `json:"cnf,omitempty"`
    jwt.RegisteredClaims
}

type AccessTokenClaims struct {
    Issuer    string        `json:"iss"`
    Subject   string        `json:"sub"`
    Audience  []string      `json:"aud"`
    ExpiresAt time.Time     `json:"exp"`
    IssuedAt  time.Time     `json:"iat"`
    NotBefore time.Time     `json:"nbf,omitempty"`
    JWTID     string        `json:"jti"`
    ClientID  string        `json:"client_id,omitempty"`
    Scope     string        `json:"scope,omitempty"`
    Role      string        `json:"role,omitempty"`
    Cnf       *Confirmation `json:"cnf,omitempty"` // For DPoP thumbprint (jkt)
}

type Confirmation struct {
    Jkt string `json:"jkt,omitempty"`
}

type WellKnownJwks struct{
	Keys	[]JWK   `json:"keys"`
}

type ClientMetadata struct {
	ClientID string `json:"client_id"`
	JWKSURI  string `json:"jwks_uri"`
}

type JWK struct {
    KeyID     string `json:"kid"`
    KeyType   string `json:"kty"`
    Crv       string `json:"crv,omitempty"`
    Algorithm string `json:"alg"`
    Use       string `json:"use"`
    N         string `json:"n,omitempty"`
    E         string `json:"e,omitempty"`
    X         string `json:"x,omitempty"`
    Y         string `json:"y,omitempty"`
}

type OAuthToken struct {
    AccessToken  string `json:"access_token,omitempty"`
    TokenType    string `json:"token_type,omitempty"`
    ExpiresIn    int    `json:"expires_in,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
    Scope        string `json:"scope,omitempty"`
    Role         string `json:"role,omitempty"`
}

// ------

type JWKS struct {
    KeyID     string `json:"kid"`
    KeyType   string `json:"kty"` // RSA
    Crv       string `json:"crv"` // Curve name for EC keys
    Algorithm string `json:"alg"` // RS256
    Use       string `json:"use"` // sig
    X         string `json:"x"`   // Base64URL-encoded X coordinate for EC keys
    Y         string `json:"y"`   // Base64URL-encoded Y coordinate for EC keys
}