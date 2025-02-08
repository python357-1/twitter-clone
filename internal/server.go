package internal

import (
	"database/sql"
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
		fmt.Println(err.Error())
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
		fmt.Println(err.Error())
		http.Error(w, err.Error(), 500)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" {
		fmt.Println(err.Error())
		http.Error(w, "username cannot be empty", 400)
		return
	}
	if password == "" {
		fmt.Println(err.Error())
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
// BEGIN "/tweets" --------------------------------------------------------------
//

func (server *TwitterCloneServer) createTweet(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err.Error())
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
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tweetText := r.FormValue("tweetText")

	_, err = server.db.dbConn.Exec("INSERT INTO tweet (body, author_id) VALUES ($1, $2)", tweetText, claims.UserId)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (server *TwitterCloneServer) getCurrentUserProfile(w http.ResponseWriter, r *http.Request) {
	var jwt string

	for _, v := range r.Cookies() {
		if v.Name == TwitterCloneCookieName {
			jwt = v.Value
		}
	}

	claims, err := server.auth.ParseJWT(jwt)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	options := PersonQueryOptionsBuilder{}
	options.AddTweets()

	user, err := server.db.GetPerson(claims.UserId, options)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.BasicJsonResponse(w, user, http.StatusOK)
}

func (server *TwitterCloneServer) searchTweets(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authorId := r.Form.Get("by")

	if authorId == "me" {
		id, err := server.auth.GetUserId(r, TwitterCloneCookieName)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		authorId = strconv.FormatInt(id, 10)
	}

	var tweets []Tweet

	err = server.db.dbConn.Select(&tweets, "SELECT * FROM tweet WHERE author_id = $1 ORDER BY tweeted DESC", authorId)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.BasicJsonResponse(w, tweets, http.StatusOK)
}

//
// END "/tweets" ---------------------------------------------------------------
//

//
// BEGIN "/users" --------------------------------------------------------------
//

func (server *TwitterCloneServer) searchUsers(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	query := r.Form.Get("query")

	var people []Person

	err = server.db.dbConn.Select(&people, "SELECT * FROM person WHERE username LIKE $1", query+"%")

	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.BasicJsonResponse(w, people, http.StatusOK)
}

func (server *TwitterCloneServer) getUserProfile(w http.ResponseWriter, r *http.Request) {
	userId, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	person, err := server.db.GetPerson(userId, PersonQueryOptionsBuilder{IncludeTweets: true})
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	utils.BasicJsonResponse(w, person, http.StatusOK)
}

//
// END "/users" ----------------------------------------------------------------
//

//
// BEGIN "/follows" ------------------------------------------------------------
//

func (server *TwitterCloneServer) followUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	currentUserId, err := server.auth.GetUserId(r, TwitterCloneCookieName)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	followUserId, err := strconv.ParseInt(r.Form.Get("userid"), 10, 64)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var follow Follow
	err = server.db.dbConn.Get(&follow, "SELECT * FROM follow WHERE follower = $1 and followed = $2", currentUserId, followUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			_, err := server.db.dbConn.Exec("INSERT INTO follow (follower, followed) VALUES ($1, $2)", currentUserId, followUserId)
			if err != nil {
				fmt.Println(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			_, err = server.db.dbConn.Exec("INSERT INTO notification (for_user, triggered_by, type) VALUES ($1, $2, $3)", followUserId, currentUserId, "follow")
			if err != nil {
				fmt.Println(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (server *TwitterCloneServer) unfollowUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	currentUserId, err := server.auth.GetUserId(r, TwitterCloneCookieName)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	followedUserId, err := strconv.ParseInt(r.Form.Get("userid"), 10, 64)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = server.db.dbConn.Exec("DELETE FROM follow WHERE follower = $1 AND followed = $2", currentUserId, followedUserId)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

//
// END "/follows" --------------------------------------------------------------
//

func (server *TwitterCloneServer) genTimeline(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	currentUserId, err := server.auth.GetUserId(r, TwitterCloneCookieName)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	startingId := r.Form.Get("startingDate")

	query := `
	SELECT * FROM tweet
	WHERE author_id in (
		SELECT person.id FROM person
		INNER JOIN follow ON follow.followed = person.id
		WHERE follow.follower = $1
	)`

	if startingId != "" {
		query += "AND tweeted < $2"
	}

	query += "ORDER BY tweeted DESC LIMIT 10"

	var tweets []Tweet
	if startingId == "" {
		err = server.db.dbConn.Select(&tweets, query, currentUserId)
	} else {
		err = server.db.dbConn.Select(&tweets, query, currentUserId, startingId)

	}

	type timelineResponse struct {
		Tweets           []Tweet   `json:"Tweets"`
		NextStartingDate time.Time `json:"nextStartingDate"`
	}

	if err != nil {

		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(tweets) == 0 {
		utils.BasicJsonResponse(w, timelineResponse{Tweets: []Tweet{}, NextStartingDate: time.Time{}}, http.StatusOK)
		return
	}

	utils.BasicJsonResponse(w, timelineResponse{Tweets: tweets, NextStartingDate: tweets[len(tweets)-1].Tweeted}, http.StatusOK)

}

func (server *TwitterCloneServer) Run() {
	http.Handle("POST /auth/register", alice.New(server.logRequest).ThenFunc(server.register))
	http.Handle("POST /auth/login", alice.New(server.logRequest).ThenFunc(server.login))
	http.HandleFunc("GET /auth/me", server.validateCookie)
	http.HandleFunc("GET /auth/logout", server.logout)

	http.HandleFunc("GET /tweets", server.searchTweets)
	http.HandleFunc("POST /tweets/", server.createTweet)

	http.HandleFunc("GET /users/{id}", server.getUserProfile)
	http.HandleFunc("GET /users", server.searchUsers)
	http.HandleFunc("GET /users/me", server.getCurrentUserProfile)

	//accepts query param "userid". makes current user follow user with id of "userid" - notify user they have a new follower
	http.HandleFunc("POST /follows", server.followUser)

	//accepts query param "userid". makes current user unfollow user with id of "userid"
	http.HandleFunc("DELETE /follows", server.unfollowUser)
	http.HandleFunc("GET /timeline", server.genTimeline)
	/*




		returns list of notifications for current user.
		possibly accept "count" query parameter to just return the number of notifications, and a "unread" bool parameter to return only read/unread notifications
		http.HandleFunc("GET /notifications")

		redirect to what notification is pointing to (i.e. tweet that was liked, message that was sent, etc)
		http.HandleFunc("GET /notifications/{id}")


		get chats and most recent message for each chat current user has
		http.HandleFunc("GET /messages")

		get messages, in reverse chronological order, between current user and userid
		http.HandleFunc("GET /messages/{userid}")

	*/

	var err error
	if server.certPath == "" || server.keyPath == "" {
		fmt.Println("running as http because no certificate or private key was supplied")
		err = http.ListenAndServe(":"+server.port, nil)
	} else {
		err = http.ListenAndServeTLS(":"+server.port, server.certPath, server.keyPath, nil)
	}

	if err != nil {
		panic(err)
	}
}
