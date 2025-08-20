package sessions

import (
	"net/http"
	"time"
)

// Handles the registration of a user by making a new cookie
func RegisterHandler(secret string, d time.Duration) (sessionId string, cookie *http.Cookie) {
	sessionId = newSessionId()
	signesSessionId := signSessionId(sessionId, secret)
	cookie = newCookie(signesSessionId, d)
	return
}

// Handles the login of a user by making a new cookie
func LoginHandler(secret string, d time.Duration) (string, *http.Cookie) {
	return RegisterHandler(secret, d)
}

// Handles the logout of a user by making an expired cookie
func LogoutHandler() *http.Cookie {
	return &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-24 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
