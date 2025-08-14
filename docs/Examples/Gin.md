```go
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/cameronmore/go-sessions/auth"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
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

	authCtx, err := auth.NewAuthContext(".env", db)
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

	protected := router.Group("/api")
	{
		protected.Use(authCtx.AuthmiddlewareGin)
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