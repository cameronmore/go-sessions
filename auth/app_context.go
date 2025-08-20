package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/cameronmore/go-sessions/sessions"
	"golang.org/x/crypto/bcrypt"
)

// An authentication manager that handles creating, accessing, and deleting sessions.
type AuthContext struct {
	Ac       sessions.AuthStore
	Secret   string
	Duration time.Duration
}

// Returns a new Authcontext authentication manager given a secret string used for cookie signing and a db connection.
func NewAuthContext(authStore sessions.AuthStore, secret string, d time.Duration) *AuthContext {
	return &AuthContext{
		Ac:       authStore,
		Secret:   secret,
		Duration: d,
	}
}

// Handles the registration of new users and returns errors to the client if a username is already taken or the username does not meet some basic criteria.
//
// The expected request to this endpoint is a JSON object with the form:
//
// { "username" : "VALUE", "password" : "PASSWORD" }
func (ac *AuthContext) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var formData map[string]interface{}
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(bodyData, &formData)
	if err != nil {
		panic(err)
	}

	hashedPassword, err := hash(formData["password"].(string))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Here we would look up in the db to make sure this username is unique and, if so,
	// hash the password and store it
	//username, password := formData["username"], formData["password"]

	// add user to DB
	var newUser sessions.User
	// TODO make this use a ULID or UUIDv4 for new user ids and then
	// change other methods to allow lookups by username
	newUser.UserId = formData["username"].(string)
	newUser.Username = formData["username"].(string)
	newUser.HashedPassword = hashedPassword
	err = ac.Ac.SaveUser(newUser)
	if err != nil {
		// log it out
		log.Printf("Error inserting user into DB: %s", err.Error())
		// better error handling is needed here for when usernames
		// don't follow certain rules or are not unique
		// but for now, this works
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sessionId, cookie := sessions.RegisterHandler(ac.Secret, ac.Duration)
	var nSession sessions.Session
	nSession.Id = sessions.SessionId(sessionId)
	nSession.ExpiresAt = cookie.Expires
	nSession.UserId = formData["username"].(string)
	err = ac.Ac.SaveSession(nSession)
	if err != nil {
		// log it out
		log.Printf("Error inserting session into DB: %s", err.Error())
		// better error handling is needed here for when usernames
		// don't follow certain rules or are not unique
		// but for now, this works
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User created"))
}

// Handles the login for users, returning an error if the user does not exist or the password is incorrect.
//
// The expected request to this endpoint is a JSON object with the form:
//
// { "username" : "VALUE", "password" : "PASSWORD" }
func (ac *AuthContext) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var formData map[string]interface{}
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(bodyData, &formData)
	if err != nil {
		panic(err)
	}

	username, password := formData["username"].(string), formData["password"].(string)

	u, err := ac.Ac.LoadUserByUserId(username, r.Context())
	if errors.Is(err, sessions.ErrUserNotFound) {
		log.Printf("Error logging in user %s: %s", username, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		// there are a number of error scenarios to handle here, bjust just declare a server error for now
		log.Printf("Error logging in user %s: %s", username, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(password))

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Password incorrect"))
		return
	}

	sessionId, cookie := sessions.LoginHandler(ac.Secret, ac.Duration)

	var nSession sessions.Session
	nSession.Id = sessions.SessionId(sessionId)
	nSession.ExpiresAt = cookie.Expires
	nSession.UserId = u.UserId
	err = ac.Ac.SaveSession(nSession)
	if err != nil {
		// log it out
		log.Printf("Error inserting session into DB: %s", err.Error())
		// better error handling is needed here for when usernames
		// don't follow certain rules or are not unique
		// but for now, this works
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	w.Write([]byte("Logged in"))
}

// Logs out a user by deleting the session id from the database and setting a new expired cookie in the response. There is
// no expected request body for this endpoint.
func (ac *AuthContext) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session_id")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Not authenticated, no session cookie", http.StatusUnauthorized)
			return
		}
	}

	sessionId, isValid := sessions.VerifyRequestSessionCookie(r, ac.Secret)

	if !isValid {
		http.Error(w, "Invalid session cookie", http.StatusUnauthorized)
	}

	err = ac.Ac.DeleteSessionById(sessionId)
	if err != nil {
		log.Printf("Error deleting session")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, sessions.LogoutHandler())
	w.Write([]byte("Logged out"))
}

// A basic middleware that checks if a user has a valid unexpired session.
func (ac *AuthContext) Authmiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie("session_id")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Not authenticated, no session cookie", http.StatusUnauthorized)
				return
			}
		}

		sessionId, isValid := sessions.VerifyRequestSessionCookie(r, ac.Secret)
		//fmt.Println(sessionId)
		if !isValid {
			http.Error(w, "Invalid session cookie", http.StatusUnauthorized)
		}

		// here we would look up the cookie in the db to get the user info

		nSession, err := ac.Ac.LoadSessionById(sessionId, r.Context())
		if err != nil {
			log.Printf("Error loading session: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
			// error retrieving session
		}

		// Check if session has expired
		if time.Now().After(nSession.ExpiresAt) {
			//if nSession.ExpiresAt.After(time.Now()) {
			log.Printf("Unauthorized: Session ID %s expired.", sessionId)
			http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
			// Delete expired session from DB asynchronously or in a cleanup routine
			go func() {
				delErr := ac.Ac.DeleteSessionById(sessionId)
				if delErr != nil {
					log.Printf("Error deleting expired session %s: %v", sessionId, delErr)
				}
			}()
			http.SetCookie(w, sessions.LogoutHandler()) // Clear client-side cookie
			return
		}

		userId := nSession.UserId
		//fmt.Println(nSession)

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userId", userId)
		ctx = context.WithValue(ctx, "session_id", sessionId)

		next.ServeHTTP(w, r.WithContext(ctx))

	})
}

func hash(password string) (string, error) {
	bts, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bts), nil
}

func passwordIsEquivilent(password string, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
