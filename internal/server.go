package internal

import (
	"fmt"
	"net/http"
	"time"

	"github.com/a-h/templ"
	"github.com/golang-jwt/jwt/v5"
	"github.com/justinas/alice"
	"github.com/python357-1/twitter-clone/templates"
)

const (
	TwitterCloneCookieName = "twtrCloneCookie"
)

func redirectUsersWithNoLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtValue := ""
		for _, v := range r.Cookies() {
			if v.Name == TwitterCloneCookieName {
				jwtValue = v.Value
			}
		}

		if jwtValue == "" {
			fmt.Println("User is not logged in - redirecting to login page")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}

		customToken := TwitterCloneClaims{}
		_, err := jwt.ParseWithClaims(jwtValue, &customToken, func(token *jwt.Token) (interface{}, error) {
			return []byte(JwtSecret), nil
		})

		if err != nil {
			//just clear user's cookie and have them sign in again
			http.SetCookie(w, &http.Cookie{
				Name: TwitterCloneCookieName,
			})
			http.Redirect(w, r, "/signup", 303)
		}
		fmt.Println(customToken.UserId)

		next.ServeHTTP(w, r)

	})
}

func skipSignInForLoggedInUsers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range r.Cookies() {
			if v.Name == TwitterCloneCookieName {
				if ValidateJWT(v.Value) {
					fmt.Println("user already signed in - skip login")
					http.Redirect(w, r, "/", 303)
				}
			}
		}

		next.ServeHTTP(w, r)
	})

}

func registerUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("lol")
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	if username == "" {
		http.Error(w, "username cannot be empty", 400)
	}
	if password == "" {
		http.Error(w, "password cannot be empty", 400)
	}

	//todo: put user in db
	auth := CreateAuthService()
	jwt := auth.CreateJWTForUser(username, RegularUser)
	http.SetCookie(w, &http.Cookie{
		Name:     TwitterCloneCookieName,
		Value:    jwt,
		Secure:   true,
		Expires:  time.Now().Add(24 * 7 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	})

	http.Redirect(w, r, "/", 303)

}

func CreateServerAndRun(port string) {
	//loginMiddleware := alice.New(redirectUsersWithNoLogin)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for _, v := range r.Cookies() {
			if v.Name == TwitterCloneCookieName && ValidateJWT(v.Value) {

			}
		}

	})
	http.Handle("/login", alice.New(skipSignInForLoggedInUsers).Then(templ.Handler(templates.Login())))
	http.HandleFunc("POST /register", registerUser)

	http.ListenAndServeTLS(port, "/home/jordan/twtrclone.jordanbc.xyz/fullchain.pem", "/home/jordan/twtrclone.jordanbc.xyz/privkey.pem", nil)
}
