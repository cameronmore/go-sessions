# Go Session Auth

> 🚧 This repository is still under construction and is pre-v1.0.0

A session-based authentication library for Go.

## Background

This library is a relatively simple implementation of session based authentication.

## Quickstart

To use this library, create a new authentication context struct by passing your secret key (for signing the session id) and a `*sql.DB` connection:

(after importing it)
```go
import "github.com/cameronmore/go-sessions/auth"
```
Then:
```go
authCtx, err := auth.NewAuthContext(YOUR_SECRET, db)
```

Then, use those to handle the authentication endpoints:

```go
http.HandleFunc("/register", authCtx.RegisterHandler)
http.HandleFunc("/logout", authCtx.LogoutHandler)
http.HandleFunc("/login", authCtx.LoginHandler)
```

And protect other endpoints by using the authentication middleware:

```go
func protectedHello(w http.ResponseWriter, r *http.Request) {
    userId := r.Context().Value("userId").(string)
	w.Write(fmt.Appendf(nil, "Hello user %s!", userId))
}

protectedHandler := authCtx.Authmiddleware(http.HandleFunc(protectedHello))
```

## Documentation

See the `docs/` directory in this repository for the full documentation. The `docs/Examples/` directory contains several examples using Gin, Chi, Gorilla/Mux, Echo, and the standard library. The most commented and guided one is the Chi router example.

> 🚧 Note that the Gin and Echo examples imports a separate middleware library that extends this one.

## Todo

There are a few key things that I need to implement before a v1.0.0 release, specifically:
- Abstract the session and user store operations to allow for more implementions (with other SQL libraries instead of SQLite as the default)
- Allowing username configuration and validation to return errors when a username does not match conventions (like having only alphanumeric characters)
- Looking up usernames to ensure uniqueness and return that error to the client
- Password validation to make sure users have strong passwords
- Adjust how I'm comparing stored passwords and incoming passwords (to prevent timing attacks for example)
- Allow users to modify the default session length

## License

This project is licensed under the Apache-2.0 license.
