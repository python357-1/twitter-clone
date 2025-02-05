package internal

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	RegularUser = 0
	AdminUser   = 1
)

type TwitterCloneClaims struct {
	UserId int64 `json:"userid,omitempty"`
	jwt.RegisteredClaims
}

type AuthService struct {
	secret string
}

func CreateAuthService(secret string) (*AuthService, error) {
	if secret == "" {
		return nil, errors.New("AuthService does not accept an empty string as a secret")
	}
	return &AuthService{
		secret: secret,
	}, nil
}

func (auth *AuthService) CreateJWTForUser(userid int64, userType int) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TwitterCloneClaims{
		userid,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	})
	fmt.Println(token)
	signedToken, err := token.SignedString([]byte(auth.secret))
	fmt.Printf("create token \"%s\"", signedToken)
	if err != nil {
		fmt.Println(err)
	}
	return signedToken
}

func (auth *AuthService) ValidateJWT(rawJwt string) bool {
	claims := TwitterCloneClaims{}
	//TODO: make this just return the parsed token
	_, err := jwt.ParseWithClaims(rawJwt, &claims, func(_ *jwt.Token) (interface{}, error) { return []byte(auth.secret), nil })
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

func (auth *AuthService) ParseJWT(rawJwt string) (*TwitterCloneClaims, error) {
	claims := TwitterCloneClaims{}
	_, err := jwt.ParseWithClaims(rawJwt, &claims, func(_ *jwt.Token) (interface{}, error) { return []byte(auth.secret), nil })

	if err != nil {
		return nil, err
	}
	return &claims, nil
}
