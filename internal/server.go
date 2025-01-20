package internal

import (
	"fmt"
	"net/http"

	"github.com/a-h/templ"
	"github.com/justinas/alice"
	"github.com/python357-1/twitter-clone/templates"
)

const (
	TwitterCloneCookieName = "twtrCloneCookie"
)

func redirectUsersWithNoLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foundCookie := false
		for _, v := range r.Cookies() {
			if v.Name == TwitterCloneCookieName {
				foundCookie = true
			}
		}

		if foundCookie == false {
			fmt.Println("User is not logged in - redirecting to login page")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	})
}

func CreateServerAndRun(port string) {
	loginMiddleware := alice.New(redirectUsersWithNoLogin)
	standardMiddleware := alice.Chain(loginMiddleware)
	http.Handle("/testroute", standardMiddleware.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("FUCK YOU")) })))
	http.Handle("/login", templ.Handler(templates.Login()))
	http.ListenAndServe(port, nil)
}
