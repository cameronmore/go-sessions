package sessions

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func newSessionId() string {
	uid := uuid.New()
	return uid.String()
}

func signSessionId(sessionId string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionId))
	signature := mac.Sum(nil)
	return fmt.Sprintf("%s.%s", sessionId, base64.URLEncoding.EncodeToString(signature))
}

func newCookie(signedSessionId string, d time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     "session_id",
		Value:    signedSessionId,
		Path:     "/",
		Expires:  time.Now().Add(d),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Returns a new cookie and session id
func NewCookieWithSessionId(secret string, d time.Duration) (cookie *http.Cookie, sessionId string) {
	sessionId = newSessionId()
	signedSessionId := signSessionId(sessionId, secret)
	cookie = newCookie(signedSessionId, d)
	return
}

// verifies a session signature from a given signed string
func VerifySessionId(requestCookieSessionId string, secret string) (string, error) {

	requestSessionId, encodedSignature, err := splitSignedSessionId(requestCookieSessionId)
	if err != nil {
		return "", err
	}
	decodedSignature, err := base64.URLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(requestSessionId))
	expectedSignature := mac.Sum(nil)

	if hmac.Equal(decodedSignature, expectedSignature) {
		return requestSessionId, nil
	}

	return "", ErrInvalidSessionSignature
}

func splitSignedSessionId(signedSessionId string) (string, string, error) {
	parts := strings.Split(signedSessionId, ".")
	if len(parts) != 2 {
		return "", "", ErrSignedSessionIdIncorrectLength
	}
	return parts[0], parts[1], nil
}

// Returns a session id if the given request contains a valid cookie, along with a helper boolean for indicating if
// the cookie is valid (true if so)
func VerifyRequestSessionCookie(r *http.Request, secret string) (string, bool) {
	requestCookie, err := r.Cookie("session_id")
	if err != nil {
		return "", false
	}
	verifiedSessionId, err := VerifySessionId(requestCookie.Value, secret)
	if err != nil {
		return "", false
	}
	return verifiedSessionId, true
}
