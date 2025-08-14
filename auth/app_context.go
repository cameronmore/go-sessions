package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/cameronmore/go-sessions/env"
	"github.com/cameronmore/go-sessions/sessions"
	"golang.org/x/crypto/bcrypt"
)

// An authentication manager that handles creating, accessing, and deleting sessions.
type AuthContext struct {
	Secret string
	DB     *sql.DB
}

// Returns a new Authcontext authentication manager given a secret string used for cookie signing and a db connection.
func NewAuthContext(envString string, db *sql.DB) (*AuthContext, error) {
	// declare secret
	secretMap, err := env.ProcessEnv(".env")
	if err != nil {
		return nil, err
	}
	secret, ok := secretMap["AUTH_SESSION_KEY"]
	if !ok {
		return nil, fmt.Errorf("AUTH_SESSION_KEY not found in .env file")
	}

	// set up session table
	newSessionTableQuery := `
	CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL
	);
	`
	_, err = db.Exec(newSessionTableQuery)
	if err != nil {
		return nil, err
	}

	// set up session table
	newUserTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
	user_id TEXT PRIMARY KEY,
	hashed_password TEXT NOT NULL
	);
	`
	_, err = db.Exec(newUserTableQuery)
	if err != nil {
		return nil, err
	}

	return &AuthContext{
		Secret: secret,
		DB:     db,
	}, nil
}

// Handles the registration of new users and returns errors to the client if a username is already taken or the username does not meet some basic criteria.
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

	newUserQuery := `
		INSERT INTO users (user_id, hashed_password)
		VALUES (?, ?)
		`
	_, err = ac.DB.Exec(newUserQuery, formData["username"].(string), hashedPassword)
	if err != nil {
		// log it out
		log.Printf("Error inserting user into DB: %s", err.Error())
		// better error handling is needed here for when usernames
		// don't follow certain rules or are not unique
		// but for now, this works
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sessionId, cookie := sessions.RegisterHandler(ac.Secret)

	newSessionQuery := `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES (?, ?, ?)
		`
	_, err = ac.DB.Exec(newSessionQuery, sessionId, formData["username"].(string), cookie.Expires)
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

	var storedHashedPassword string
	err = ac.DB.QueryRowContext(r.Context(), "SELECT hashed_password FROM users WHERE user_id = ?", username).Scan(&storedHashedPassword)
	if err != nil {
		// there are a number of error scenarios to handle here, bjust just declare a server error for now
		log.Printf("Error logging in user %s: %s", username, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// storedPassword != hashedPassword
	if !passwordIsEquivilent(password, storedHashedPassword) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Password incorrect"))
		return
	}

	sessionId, cookie := sessions.LoginHandler(ac.Secret)

	newSessionQuery := `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES (?, ?, ?)
		`
	_, err = ac.DB.Exec(newSessionQuery, sessionId, formData["username"].(string), cookie.Expires)
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

// Logs out a user by deleting the session id from the database and setting a new expired cookie in the response.
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

	deleteCookieQuery := `
	DELETE FROM sessions
	WHERE id = ?
	`

	result, err := ac.DB.Exec(deleteCookieQuery, sessionId)
	if err != nil {
		log.Printf("Error removing session from db: %s", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected from removing session: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if affected == 0 {
		log.Printf("Error deleting session, no session found")
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

		if !isValid {
			http.Error(w, "Invalid session cookie", http.StatusUnauthorized)
		}

		// here we would look up the cookie in the db to get the user info

		var storedUserID string
		var expiresAt time.Time
		query := `SELECT user_id, expires_at FROM sessions WHERE id = ?`
		err = ac.DB.QueryRowContext(r.Context(), query, sessionId).Scan(&storedUserID, &expiresAt)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Unauthorized: Session ID %s not found in DB.", sessionId)
				http.Error(w, "Unauthorized: Session not found", http.StatusUnauthorized)
				http.SetCookie(w, sessions.LogoutHandler()) // Clear client-side cookie if not found in DB
				return
			}
			log.Printf("Database error looking up session %s: %v", sessionId, err)
			http.Error(w, "Internal server error during authentication", http.StatusInternalServerError)
			return
		}

		// Check if session has expired
		if time.Now().After(expiresAt) {
			log.Printf("Unauthorized: Session ID %s expired.", sessionId)
			http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
			// Delete expired session from DB asynchronously or in a cleanup routine
			go func() {
				_, delErr := ac.DB.Exec("DELETE FROM sessions WHERE id = ?", sessionId)
				if delErr != nil {
					log.Printf("Error deleting expired session %s: %v", sessionId, delErr)
				}
			}()
			http.SetCookie(w, sessions.LogoutHandler()) // Clear client-side cookie
			return
		}

		userId := storedUserID

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
