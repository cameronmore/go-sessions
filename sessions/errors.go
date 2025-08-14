package sessions

import "errors"

var ErrSignedSessionIdIncorrectLength = errors.New("The signed session id is not the correct length")

var ErrInvalidSessionSignature = errors.New("The signed session id had an invalid signature")
