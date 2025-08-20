package sessions

import "errors"

var ErrSignedSessionIdIncorrectLength = errors.New("The signed session id is not the correct length")

var ErrInvalidSessionSignature = errors.New("The signed session id had an invalid signature")

var ErrUserNotFound = errors.New("The user was not found with that username or id")

var ErrSessionNotFound = errors.New("The session was not found")
