```go
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/cameronmore/go-sessions/auth"
	"github.com/cameronmore/go-sessions/env"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// set up a connection to the database
	db, err := sql.Open("sqlite3", "db.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to the db: %v", err)
	}

	fmt.Println("Sucessfully connected to db")

	// declare secret
	secretMap, err := env.ProcessEnv(".env")
	if err != nil {
		panic(err)
	}
	secret, ok := secretMap["AUTH_SESSION_KEY"]
	if !ok {
		panic(errors.New("Auth key not found"))
	}

	// Define a new SQLite store that implements the interface
	sqliteAuthStore, err := auth.NewSQLiteStore(db, secret, 7 * 24 * time.Hour)
	if err != nil {
		panic(err)
	}
	// pass that store to the Authcontext that expects the interface
	var authCtx auth.AuthContext
	authCtx.Ac = sqliteAuthStore

	// Now define your router. In this example, I'm using Chi
	r := chi.NewRouter()

	r.Use(middleware.Logger)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	// Here, we define the endpoints that are used for authentication:
	// - register
	// - login
	// - logout
	authRouter := chi.NewRouter()
	authRouter.Post("/login", authCtx.LoginHandler)
	authRouter.Post("/register", authCtx.RegisterHandler)
	authRouter.Get("/logout", authCtx.LogoutHandler)
	// I'm mounting them all to the /auth endpoint, so a user can hit /auth/register to make a new account and
	// then hit /api/... to access any protected data
	r.Mount("/auth", authRouter)

	// here we're defining the actual protected endpoints by using the authentication context's auth middleware
	apiRouter := chi.NewRouter()
	apiRouter.Use(authCtx.Authmiddleware)
	apiRouter.Get("/userData", func(w http.ResponseWriter, r *http.Request) {
		// That middleware provices the user id as a context so you know what client
		// is making the request.
		userId := r.Context().Value("userId").(string)
		w.Write(fmt.Appendf(nil, "You requested user data for %s", userId))
	})

	// and we mount this protected router to the main router
	r.Mount("/api", apiRouter)

	// and serve the application
	http.ListenAndServe(":3000", r)

}
```