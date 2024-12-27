package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("your-secret-key-here") // In production, use environment variable

type Claims struct {
	UserID      int64  `json:"user_id"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	Country     string `json:"Country"`
	Phone       string `json:"Phone"`
	Profile_Url bool   `json:"Profile_Url"`

	jwt.RegisteredClaims
}

func GenerateToken(userID int64, email, firstName string) (string, error) {
	claims := Claims{
		UserID:    userID,
		Email:     email,
		FirstName: firstName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}
