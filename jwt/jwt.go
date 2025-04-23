package jwt

import (
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTPrivate struct {
	privateKey      *rsa.PrivateKey
	accessDuration  time.Duration
	refreshDuration time.Duration
}

type JWTPublic struct {
	publicKey *rsa.PublicKey
}

type AccessClaims struct {
	UserID  int64 `json:"user_id"`
	IsAdmin bool  `json:"is_admin"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID int64 `json:"user_id"`
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

func NewPublic(keyPath string) (*JWTPublic, error) {
	key, err := getPublicKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("JWT - NewPublic - getPublicKey: %w", err)
	}
	return &JWTPublic{publicKey: key}, nil
}

func NewPrivate(keyPath string, accessDuration time.Duration, refreshDuration time.Duration) (*JWTPrivate, error) {
	key, err := getPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("JWT - NewPublic - getPublicKey: %w", err)
	}
	return &JWTPrivate{privateKey: key, accessDuration: accessDuration, refreshDuration: refreshDuration}, nil
}

func (j *JWTPrivate) GenerateAccessToken(userID int64, isAdmin bool) (string, error) {
	claims := &AccessClaims{
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

func (j *JWTPrivate) GenerateRefreshToken(userID int64) (string, error) {
	claims := &RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.refreshDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.privateKey)
}

func (j *JWTPublic) ParseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrInvalidKey
	}

	return claims, nil
}
