package sessions

import (
	"context"
	"time"
)

type User struct {
	Username       string
	UserId         string
	HashedPassword string
}

type SessionId string

func SessionIdFromString(s string) SessionId {
	return SessionId(s)
}

type Session struct {
	Id        SessionId
	UserId    string
	ExpiresAt time.Time
}

type AuthStore interface {
	SaveUser(User) error
	LoadUserByUserId(string, context.Context) (User, error)
	// DeleteUserByUserId(string) error
	// UpdateUser(User) error

	SaveSession(Session) error
	LoadSessionById(string, context.Context) (Session, error)
	DeleteSessionById(string) error
}
