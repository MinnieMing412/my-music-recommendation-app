package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	redirectURI  = "http://localhost:3000/callback"
	authEndpoint = "https://accounts.spotify.com/authorize"
	spotify_token_url = "https://accounts.spotify.com/api/token"
	token_file = "token.json"
)

var (
	// Mutex to synchronize access to the global variable
	mu          sync.Mutex
	refreshToken RefreshToken
	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
)

type RefreshToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func HomeHandler(c *gin.Context) {
	c.String(200, "Hello, World!")
}

func LoginHandler(c *gin.Context) {
	state := generateRandomString(16)
	scope := "user-read-private user-read-email"
	// Construct the authorization URL
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", clientID)
	params.Add("scope", scope)
	params.Add("redirect_uri", redirectURI)
	params.Add("state", state)
	authURL := fmt.Sprintf("%s?%s", authEndpoint, params.Encode())
	c.Redirect(http.StatusFound, authURL)
}

func CallbackHandler(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	if state == "" {
		// Redirect to error if state is missing
		c.Redirect(http.StatusFound, "/#?error=state_mismatch")
		return
	}

	// Prepare POST form data
	form := url.Values{}
	form.Add("code", code)
	form.Add("redirect_uri", redirectURI)
	form.Add("grant_type", "authorization_code")

	// Create HTTP POST request to Spotify API
	req, err := http.NewRequest("POST", spotify_token_url, bytes.NewBufferString(form.Encode()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", authHeader)

	// Make the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request"})
		return
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode != http.StatusOK {
		c.JSON(resp.StatusCode, gin.H{"error": "Failed to retrieve token"})
		return
	}

	// Parse the response body
	var result RefreshToken
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	mu.Lock()
	refreshToken.AccessToken = result.AccessToken
	refreshToken.RefreshToken = result.RefreshToken
	mu.Unlock()

	log.Printf("Tokens successfully retrieved and stored: AccessToken=%s, RefreshToken=%s\n", refreshToken.AccessToken, refreshToken.RefreshToken)
	saveToken(refreshToken)
	c.JSON(http.StatusOK, result)
}

func GetAccessTokenHandler(c *gin.Context) {
	mu.Lock()
	defer mu.Unlock()

	refreshToken, err := loadToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	response := map[string]string{
		"access_token":  refreshToken.AccessToken,
		"refresh_token": refreshToken.RefreshToken,
	}
	c.JSON(http.StatusOK, response)
}

func RefreshTokenHandler(c *gin.Context) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken.RefreshToken)
	form.Set("client_id", clientID)
	fmt.Println(form)

	req, err := http.NewRequest("POST", spotify_token_url, bytes.NewBufferString(form.Encode()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", authHeader)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("failed to send request: %w", err)})
		return
	}
	defer resp.Body.Close()

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		c.JSON(resp.StatusCode, gin.H{"error": fmt.Errorf("failed with status %s and code: %d", resp.Status, resp.StatusCode)})
		return
	}

	// Parse the response body
	var tokenData RefreshToken
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("failed to parse response: %w", err)})
		return
	}

	saveToken(tokenData)

	response := map[string]string{
		"access_token":  refreshToken.AccessToken,
		"refresh_token": refreshToken.RefreshToken,
	}
	c.JSON(http.StatusOK, response)
}

func saveToken(refreshToken RefreshToken) {
	// Open or create a file to write the JSON output
	file, err := os.Create(token_file)
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	// Create a JSON encoder and write the token as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Add indentation for pretty-printing
	if err := encoder.Encode(refreshToken); err != nil {
		log.Fatalf("Failed to encode JSON: %v", err)
	}

	log.Println("Token written to refresh_token.json")
}

func loadToken() (RefreshToken, error) {
	var refreshToken RefreshToken
	file, err := os.Open(token_file)
	if err != nil {
		return refreshToken, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Read the file content
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return refreshToken, fmt.Errorf("failed to read file: %v", err)
	}

	// Unmarshal JSON into the struct
	if err := json.Unmarshal(content, &refreshToken); err != nil {
		return refreshToken, fmt.Errorf("failed to decode JSON: %v", err)
	}

	return refreshToken, nil
}