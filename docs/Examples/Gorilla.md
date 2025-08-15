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
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "db.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to the db: %v", err)
	}

	fmt.Println("Successfully connected to db")

    // declare secret
	secretMap, err := env.ProcessEnv(".env")
	if err != nil {
		panic(err)
	}
	secret, ok := secretMap["AUTH_SESSION_KEY"]
	if !ok {
		panic(errors.New("Auth key not found"))
	}

	authCtx, err := auth.NewAuthContext(secret, db)
	if err != nil {
		panic(err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	}).Methods("GET")

	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/login", authCtx.LoginHandler).Methods("POST")
	authRouter.HandleFunc("/register", authCtx.RegisterHandler).Methods("POST")
	authRouter.HandleFunc("/logout", authCtx.LogoutHandler).Methods("GET")

	apiRouter := r.PathPrefix("/api").Subrouter()

	apiRouter.Use(authCtx.Authmiddleware)

	apiRouter.HandleFunc("/userData", func(w http.ResponseWriter, r *http.Request) {

		userId := r.Context().Value("userId").(string)
		w.Write(fmt.Appendf(nil, "You requested user data for %s", userId))
	}).Methods("GET")

	apiRouter.Use(authCtx.Authmiddleware)

	apiRouter.HandleFunc("/anotherProtectedEndpoint", func(w http.ResponseWriter, r *http.Request) {
		userId := r.Context().Value("userId").(string)
		w.Write(fmt.Appendf(nil, "This is another protected endpoint for %s", userId))
	}).Methods("GET")

	log.Printf("Server starting on port :3003")
	err = http.ListenAndServe(":3003", r)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```