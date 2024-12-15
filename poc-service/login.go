package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

const (
	redirectURI  = "http://localhost:3000/callback"
	authEndpoint = "https://accounts.spotify.com/authorize"
	spotify_token_url = "https://accounts.spotify.com/api/token"
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

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello, World!")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
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
	http.Redirect(w, r, authURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if state == "" {
		// Redirect to error if state is missing
		http.Redirect(w, r, "/#?error=state_mismatch", http.StatusFound)
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
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", authHeader)

	// Make the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to retrieve token", resp.StatusCode)
		return
	}

	// Parse the response body
	var result RefreshToken
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		http.Error(w, "Failed to parse response", http.StatusInternalServerError)
		return
	}

	mu.Lock()
	refreshToken.AccessToken = result.AccessToken
	refreshToken.RefreshToken = result.RefreshToken
	mu.Unlock()

	log.Printf("Tokens successfully retrieved and stored: AccessToken=%s, RefreshToken=%s\n", refreshToken.AccessToken, refreshToken.RefreshToken)

	// Return the result as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func getAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	if refreshToken.AccessToken == "" {
		http.Error(w, "Access token not set", http.StatusNotFound)
		return
	}

	response := map[string]string{
		"access_token":  refreshToken.AccessToken,
		"refresh_token": refreshToken.RefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getRefreshToken() error {
	// Form data for the request body
	
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken.RefreshToken)
	form.Set("client_id", clientID)
	fmt.Println(form)

	// Create the HTTP POST request
	req, err := http.NewRequest("POST", spotify_token_url, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", authHeader)


	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed with status %s and code: %d", resp.Status, resp.StatusCode)
	}

	// Parse the response body
	var tokenData RefreshToken
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Save tokens (In Go, you can use a file, a database, or an in-memory cache)
	fmt.Println("Access Token:", tokenData.AccessToken)
	if tokenData.RefreshToken != "" {
		fmt.Println("Refresh Token:", tokenData.RefreshToken)
	}

	return nil
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := getRefreshToken()
	if err != nil {
		http.Error(w, fmt.Errorf("failed to refresh token: %s", err).Error(), http.StatusInternalServerError)
		return
	}

	msg := fmt.Sprintf("Token refreshed successfully! New refresh token is: %s, new access token is: %s", refreshToken.RefreshToken, refreshToken.AccessToken)
	fmt.Fprintln(w, msg)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/callback", callbackHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/get-token", getAccessTokenHandler)
	r.HandleFunc("/refresh", refreshTokenHandler)
	
	// Start the server
	fmt.Println("Server is running on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}
