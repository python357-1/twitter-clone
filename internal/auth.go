package internal

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	RegularUser = 0
	AdminUser   = 1

	jwtSecret = "the boys going to the ice cream shop love mustard flavored ice cream"
)

type TwitterCloneClaims struct {
	UserId string `json:"userid,omitempty"`
	jwt.RegisteredClaims
}

type User struct {
	Username string
	UserId   string
}

type AuthService struct {
	secret string
}

func CreateAuthService(secret string) *AuthService {
	return &AuthService{
		secret: secret,
	}
}

func (as *AuthService) CreateJWTForUser(userid string, userType int) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TwitterCloneClaims{
		userid,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	})
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		fmt.Println("FUCK YOUUUUU")
	}
	return signedToken
}
