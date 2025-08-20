```go
package main

import (
	"database/sql"
	"errors"
	"github.com/cameronmore/go-sessions/auth"
	"github.com/cameronmore/go-sessions/env"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
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
	sqliteAuthStore, err := auth.NewSQLiteStore(db)
	if err != nil {
		panic(err)
	}
	// pass that store to the Authcontext that expects the interface
	authCtx := auth.NewAuthContext(sqliteAuthStore, secret, 7*24*time.Hour)

	http.HandleFunc("/register", authCtx.RegisterHandler)
	http.HandleFunc("/logout", authCtx.LogoutHandler)
	http.HandleFunc("/login", authCtx.LoginHandler)

	protectedHandler := authCtx.Authmiddleware(http.HandlerFunc(protectedHello))
	http.Handle("/hello", protectedHandler)

	err = http.ListenAndServe(":3333", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}

}

func protectedHello(w http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value("userId").(string)
	w.Write(fmt.Appendf(nil, "Hello user %s!", userId))
}
```