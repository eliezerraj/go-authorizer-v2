package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"os"
	"log"
)

type CustomClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func main() {
    privateKeyPEMPath := "./ec256/ec256_private_key.pem"

    pemBytes, err := os.ReadFile(privateKeyPEMPath)
    if err != nil {
        log.Printf("error reading private key PEM file: %v", err)
        fmt.Println("Failed to read private key PEM file")
        return
    }

    privateKey, err := jwt.ParseECPrivateKeyFromPEM(pemBytes)
    if err != nil {
        log.Printf("error parsing private key PEM file: %v", err)
        fmt.Println("Failed to parse private key PEM file")
        return
    }

    claims := CustomClaims{
		UserID: "roadcard",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "roadcard-service-pix-out",
			Subject:   "roadcard",
			Audience:  jwt.ClaimStrings{"https://roadcard.com.br"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:    uuid.New().String(),
		},
	}
    fmt.Printf("Claims: %+v\n", claims)

    token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		log.Printf("error signing token: %v", err)
		fmt.Println("Failed to sign token")
		return
	}
    fmt.Printf("Signed Token: %s\n", signedToken)
}