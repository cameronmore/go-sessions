```go
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/cameronmore/go-session-adapters/echo_mw"
	"github.com/cameronmore/go-sessions/auth"
	"github.com/cameronmore/go-sessions/env"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

	// Define a new SQLite store that implements the interface
	sqliteAuthStore, err := auth.NewSQLiteStore(db)
	if err != nil {
		panic(err)
	}
	// pass that store to the Authcontext that expects the interface
	authCtx := auth.NewAuthContext(sqliteAuthStore, secret, 7*24*time.Hour)

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello World!")
	})

	authGroup := e.Group("/auth")
	authGroup.POST("/login", echo.WrapHandler(http.HandlerFunc(authCtx.LoginHandler)))
	authGroup.POST("/register", echo.WrapHandler(http.HandlerFunc(authCtx.RegisterHandler)))
	authGroup.GET("/logout", echo.WrapHandler(http.HandlerFunc(authCtx.LogoutHandler)))

	apiGroup := e.Group("/api")

	apiGroup.Use(echomw.EchoAuthMiddleware(authCtx))

	apiGroup.GET("/userData", func(c echo.Context) error {
		userId, ok := c.Get("userId").(string)
		if !ok {
			return echo.NewHTTPError(http.StatusInternalServerError, "User ID not found in context")
		}
		return c.String(http.StatusOK, fmt.Sprintf("You requested user data for %s", userId))
	})

	apiGroup.GET("/anotherProtectedEndpoint", func(c echo.Context) error {
		userId, ok := c.Get("userId").(string)
		if !ok {
			return echo.NewHTTPError(http.StatusInternalServerError, "User ID not found in context")
		}
		return c.String(http.StatusOK, fmt.Sprintf("This is another protected endpoint for %s", userId))
	})

	log.Printf("Server starting on port :3004")
	err = e.Start(":3004")
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```