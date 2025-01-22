package internal

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	RegularUser = 0
	AdminUser   = 1
	JwtSecret   = "the boys going to the ice cream shop love mustard flavored ice cream"
)

type TwitterCloneClaims struct {
	UserId string `json:"userid,omitempty"`
	jwt.RegisteredClaims
}

type User struct {
	Username string
	UserId   string
}

type AuthService struct{}

func CreateAuthService() *AuthService {
	return &AuthService{}
}

func (as *AuthService) CreateJWTForUser(userid string, userType int) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TwitterCloneClaims{
		userid,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	})
	fmt.Println(token)
	signedToken, err := token.SignedString([]byte(JwtSecret))
	fmt.Println(signedToken)
	if err != nil {
		fmt.Println(err)
	}
	return signedToken
}

func ValidateJWT(rawJwt string) bool {
	claims := TwitterCloneClaims{}
	//TODO: make this just return the parsed token
	_, err := jwt.ParseWithClaims(rawJwt, &claims, func(_ *jwt.Token) (interface{}, error) { return []byte(JwtSecret), nil })
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}
