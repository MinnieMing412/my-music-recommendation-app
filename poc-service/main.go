package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Start the server
	fmt.Println("Server is running on http://localhost:3000")
	
	r.GET("/", HomeHandler)
	r.GET("/callback", CallbackHandler)
	r.GET("/login", LoginHandler)
	r.GET("/token", GetAccessTokenHandler)
	r.GET("/refresh", RefreshTokenHandler)
	r.GET("/current-user", CurrentUserHandler)
	
	log.Fatal(http.ListenAndServe(":3000", r))
}