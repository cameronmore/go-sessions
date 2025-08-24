# Go Session Auth

> 🚧 This repository is still under construction and is pre-v1.0.0

A session-based authentication library for Go.

## Background

This library is a relatively simple implementation of session based authentication.

## Quickstart

To use this library, create a new authentication context struct by passing your secret key (for signing the session id) and something that implements the sessions.AuthStore interface (so far, there are SQLite and Postgres implementations):

(after importing it)
```go
import "github.com/cameronmore/go-sessions/auth"
```
Then:
```go
// Define a new SQLite store that implements the interface
sqliteAuthStore, err := auth.NewSQLiteStore(db, secret, 7 * 24 * time.Hour)
if err != nil {
	panic(err)
}
// pass that store to the Authcontext that expects the interface
var authCtx auth.AuthContext
authCtx.Ac = sqliteAuthStore
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

Please see `main.go` for an up-to-date and working example with Chi.

## Documentation

> 🚧 The `main.go` file in this repository should always contain a working example, even if the other documentation lags behind.

See the `docs/` directory in this repository for the full documentation. The `docs/Examples/` directory contains several examples using Gin, Chi, Gorilla/Mux, Echo, and the standard library. The most commented and guided one is the Chi router example.

> 🚧 Note that the Gin and Echo examples imports a separate middleware library that extends this one. They are also not working at the moment.

## Todo

There are a few key things that I need to implement before a v1.0.0 release, specifically:
- [x] Abstract the session and user store operations to allow for more implementions (with other SQL libraries instead of SQLite as the default)
- [ ]  Allowing username configuration and validation to return errors when a username does not match conventions (like having only alphanumeric characters)
- [x] Looking up usernames to ensure uniqueness and return that error to the client
- [ ] Password validation to make sure users have strong passwords
- [ ] Adjust how I'm comparing stored hashed passwords and incoming passwords (to prevent timing attacks for example)
- [x] Allow users to modify the default session length
- [x] Change the way i'm generating user ids and how I'm looking up users by username v. user id (now done with ULIDs)
- [ ] Improve logging across the board

## License

This project is licensed under the Apache-2.0 license.
