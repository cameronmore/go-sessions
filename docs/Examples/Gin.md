```go
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/cameronmore/go-session-adapters/gin_mw"
	"github.com/cameronmore/go-sessions/auth"
	"github.com/cameronmore/go-sessions/env"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
)

func main() {
	db, err := sql.Open("sqlite3", "db.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
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
		log.Fatalf("Error creating AuthContext: %v", err)
	}

	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	router.POST("/register", gin.WrapF(authCtx.RegisterHandler))
	router.POST("/login", gin.WrapF(authCtx.LoginHandler))
	router.GET("/logout", gin.WrapF(authCtx.LogoutHandler))
	// here, we need to wrap the auth context in the Gin adapter
	var ginAuthCtx ginmw.GinAuthContext
	ginAuthCtx.Ac = authCtx
	// and now we can use it in this route group like so:
	protected := router.Group("/api")
	{
		protected.Use(ginAuthCtx.AuthmiddlewareGin)
		protected.GET("/hello", protectedHelloGin)
	}

	port := ":3333"
	fmt.Printf("Gin server listening on %s...\n", port)
	err = router.Run(port)
	if err != nil {
		log.Fatalf("Gin server failed to start: %v", err)
	}
}

func protectedHelloGin(c *gin.Context) {
	userIdVal, exists := c.Get("userId")
	if !exists {
		c.String(http.StatusInternalServerError, "User ID not found in Gin context")
		return
	}
	userId, ok := userIdVal.(string)
	if !ok {
		c.String(http.StatusInternalServerError, "User ID in Gin context is not a string")
		return
	}
	c.String(http.StatusOK, "Hello user %s!", userId)
}
```