# Go Session Auth

A session-based authentication library for Go.

## Background

This library is a relatively simple implementation of session based authentication.

## Usage

### Quickstart

To use this library, create a new authentication context struct by passing it the path to a secret `.env` file and a `sql.DB` connection:

```go
authCtx, err := auth.NewAuthContext(".env", db)
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

### Documentation

See the `docs/` directory in this repository for the full documentation. The `docs/Examples/` directory contains several examples using Gin, Chi, and the standard library. The most commented and guided one is the Chi router example.

### License

This project is licensed under the Apache-2.0 license.
