package internal

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/justinas/alice"
	_ "github.com/lib/pq"
	"github.com/python357-1/twitter-clone/utils"
	"golang.org/x/crypto/bcrypt"
)

const (
	TwitterCloneCookieName = "twtrCloneCookie"
)

type TwitterCloneServerOptions struct {
	Port             string // May not be set; default 443
	Secret           string // Must be set
	ConnectionString string // Must be set
	CertPath         string // SSL Certificate path; Must be set
	KeyPath          string // SSL Private key path: Must be set
}

type TwitterCloneServer struct {
	port     string
	auth     *AuthService
	db       TwitterCloneDB
	certPath string
	keyPath  string
}

func (server *TwitterCloneServer) redirectUsersWithNoLogin(next http.Handler) http.Handler {
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
			return []byte(server.auth.secret), nil
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

func (server *TwitterCloneServer) skipSignInForLoggedInUsers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range r.Cookies() {
			if v.Name == TwitterCloneCookieName {
				if server.auth.ValidateJWT(v.Value) {
					fmt.Println("user already signed in - skip login")
					http.Redirect(w, r, "/", 303)
				}
			}
		}

		next.ServeHTTP(w, r)
	})

}

func CreateServer(options TwitterCloneServerOptions) (*TwitterCloneServer, error) {
	port := options.Port
	if port == "" {
		port = "443"
	}

	auth, err := CreateAuthService(options.Secret)
	if err != nil {
		return nil, err
	}

	db, err := sqlx.Connect("postgres", options.ConnectionString)
	if err != nil {
		return nil, err
	}

	if options.CertPath == "" {
		return nil, errors.New("SSL certificate path must be set to a value (got \"\")")
	}

	if options.CertPath == "" {
		return nil, errors.New("SSL private key path must be set to a value (got \"\")")
	}

	db.MustExec(schema)

	return &TwitterCloneServer{
		port:     port,
		auth:     auth,
		db:       CreateDBInstance(db),
		certPath: options.CertPath,
		keyPath:  options.KeyPath,
	}, nil
}

func (server *TwitterCloneServer) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s\n", r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
	})

}

//
// BEGIN "/auth" ---------------------------------------------------------------
//

func (server *TwitterCloneServer) validateCookie(w http.ResponseWriter, r *http.Request) {
	var jwt string

	type AuthResponse struct {
		IsAuthenticated bool   `json:"isAuthenticated"`
		User            string `json:"user"`
	}

	for _, v := range r.Cookies() {
		if v.Name == TwitterCloneCookieName {
			jwt = v.Value
			break
		}
	}

	if jwt == "" {
		fmt.Println("jwt empty")
		utils.BasicJsonResponse(w, AuthResponse{IsAuthenticated: false, User: "unknown"}, http.StatusBadRequest)
		return
	}

	claims, err := server.auth.ParseJWT(jwt)

	if err != nil {
		fmt.Println("jwt invalid")
		utils.BasicJsonResponse(w, AuthResponse{IsAuthenticated: false, User: "unknown"}, http.StatusBadRequest)
		return
	}

	utils.BasicJsonResponse(w, AuthResponse{IsAuthenticated: true, User: strconv.FormatInt(claims.UserId, 10)}, http.StatusOK)
}

func (server *TwitterCloneServer) register(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		utils.BasicJsonResponse(w, utils.ErrorResponse{Types: []string{"emailInvalid"}}, http.StatusBadRequest)
		return
	}

	var emailUsernameStatus struct {
		EmailExists    bool `db:"email_exists"`
		UsernameExists bool `db:"username_exists"`
	}

	query := `
		select
			exists (select 1 from person where email = $1) as email_exists,
			exists (select 1 from person where username = $2) as username_exists;`

	server.db.dbConn.Get(&emailUsernameStatus, query, email, username)

	errorResponse := utils.ErrorResponse{Types: []string{}}
	if emailUsernameStatus.EmailExists {
		errorResponse.Types = append(errorResponse.Types, "emailInUse")
	}

	if emailUsernameStatus.UsernameExists {
		errorResponse.Types = append(errorResponse.Types, "usernameInUse")
	}

	if emailUsernameStatus.EmailExists || emailUsernameStatus.UsernameExists {
		utils.BasicJsonResponse(w, errorResponse, http.StatusBadRequest)
		return
	}

	server.db.dbConn.Exec("INSERT INTO person (username, password, email) VALUES ($1, $2, $3);", username, utils.HashPassword(password), email)

	var person Person

	if err := server.db.dbConn.Get(&person, "SELECT * FROM person WHERE username = $1", username); err != nil {
		panic(err) // this shouldnt happen, for obvious reasons
	}

	jwt := server.auth.CreateJWTForUser(person.Id, RegularUser)
	http.SetCookie(w, &http.Cookie{
		Name:     TwitterCloneCookieName,
		Value:    jwt,
		Secure:   true,
		Expires:  time.Now().Add(24 * 7 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
}

func (server *TwitterCloneServer) login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" {
		http.Error(w, "username cannot be empty", 400)
		return
	}
	if password == "" {
		http.Error(w, "password cannot be empty", 400)
		return
	}

	var person Person
	err = server.db.dbConn.Get(&person, "SELECT * FROM person WHERE username = $1", username)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			return
		} else {
			panic(err)
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(person.PasswordHash), []byte(password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt := server.auth.CreateJWTForUser(person.Id, RegularUser)
	http.SetCookie(w, &http.Cookie{
		Name:     TwitterCloneCookieName,
		Value:    jwt,
		Secure:   true,
		Expires:  time.Now().Add(24 * 7 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})
	_, err = fmt.Fprintf(w, "login ok for user \"%s\"", username)
	if err != nil {
		fmt.Fprintf(w, "%s", err.Error())
	}
}

func (server *TwitterCloneServer) logout(w http.ResponseWriter, r *http.Request) {

}

//
// END "/auth" -----------------------------------------------------------------
//

//
// BEGIN "/tweet" --------------------------------------------------------------
//

func (server *TwitterCloneServer) createTweet(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	var jwt string

	for _, v := range r.Cookies() {
		if v.Name == TwitterCloneCookieName {
			jwt = v.Value
		}
	}

	claims, err := server.auth.ParseJWT(jwt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tweetText := r.FormValue("tweetText")

	_, err = server.db.dbConn.Exec("INSERT INTO tweet (body, author_id) VALUES ($1, $2)", tweetText, claims.UserId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (server *TwitterCloneServer) getCurrentUserWithTweets(w http.ResponseWriter, r *http.Request) {
	var jwt string

	for _, v := range r.Cookies() {
		if v.Name == TwitterCloneCookieName {
			jwt = v.Value
		}
	}

	claims, err := server.auth.ParseJWT(jwt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	options := PersonQueryOptionsBuilder{}
	options.AddTweets()

	user, err := server.db.GetPerson(claims.UserId, options)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.BasicJsonResponse(w, user, http.StatusOK)
}

func (server *TwitterCloneServer) Run() {
	//http.Handle("/", alice.New(server.logRequest).ThenFunc(func(w http.ResponseWriter, r *http.Request) {
	//	for _, v := range r.Cookies() {
	//		if v.Name == TwitterCloneCookieName && server.auth.ValidateJWT(v.Value) {
	//			//TODO: get person data from db
	//			fmt.Fprintln(w, "'sall good man")
	//		}
	//	}

	//}))

	http.Handle("POST /auth/register", alice.New(server.logRequest).ThenFunc(server.register))
	http.Handle("POST /auth/login", alice.New(server.logRequest).ThenFunc(server.login))
	//	http.	 Handle("GET /auth/login")
	http.HandleFunc("GET /auth/me", server.validateCookie)
	http.HandleFunc("GET /auth/logout", server.logout)

	http.HandleFunc("POST /tweets/", server.createTweet)
	http.HandleFunc("GET /tweets/me", server.getCurrentUserWithTweets)

	err := http.ListenAndServeTLS(":"+server.port, server.certPath, server.keyPath, nil)
	if err != nil {
		panic(err)
	}
}
