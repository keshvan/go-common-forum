package jwt

import (
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	accessDuration  time.Duration
	refreshDuration time.Duration
}

type Claims struct {
	UserID  int64 `json:"user_id"`
	IsAdmin bool  `json:"is_admin"`
	jwt.RegisteredClaims
}

func getPublicKey(path string) (*rsa.PublicKey, error) {
	pubBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func getPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func NewPublic(keyPath string) (*JWT, error) {
	key, err := getPublicKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("JWT - NewPublic - getPublicKey: %w", err)
	}
	return &JWT{privateKey: nil, publicKey: key, accessDuration: 0, refreshDuration: 0}, nil
}

func NewPrivate(keyPath string, accessDuration time.Duration, refreshDuration time.Duration) (*JWT, error) {
	key, err := getPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("JWT - NewPublic - getPublicKey: %w", err)
	}
	return &JWT{privateKey: key, publicKey: nil, accessDuration: accessDuration, refreshDuration: refreshDuration}, nil
}

func (j *JWT) GenerateAccessToken(userID int64, isAdmin bool) (string, error) {
	claims := &Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.accessDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.privateKey)
}

func (j *JWT) GenerateRefreshToken(userID int64, isAdmin bool) (string, error) {
	claims := &Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.refreshDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.privateKey)
}

func (j *JWT) ParseToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrInvalidKey
	}

	return claims, nil
}
