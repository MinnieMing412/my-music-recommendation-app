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
)

var (
	// Mutex to synchronize access to the global variable
	mu          sync.Mutex
	accessToken string
)

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
	clientID := os.Getenv("CLIENT_ID")
	// Construct the authorization URL
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", clientID)
	params.Add("scope", scope)
	params.Add("redirect_uri", redirectURI)
	params.Add("state", state)
	authURL := fmt.Sprintf("%s?%s", authEndpoint, params.Encode())
	fmt.Println(authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if state == "" {
		// Redirect to error if state is missing
		http.Redirect(w, r, "/#?error=state_mismatch", http.StatusFound)
		return
	}

	// Prepare authorization header
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))

	// Prepare POST form data
	form := url.Values{}
	form.Add("code", code)
	form.Add("redirect_uri", redirectURI)
	form.Add("grant_type", "authorization_code")

	// Create HTTP POST request to Spotify API
	req, err := http.NewRequest("POST", "https://accounts.spotify.com/api/token", bytes.NewBufferString(form.Encode()))
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
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		http.Error(w, "Failed to parse response", http.StatusInternalServerError)
		return
	}

	// Retrieve and store the access token in the global variable
	if token, ok := result["access_token"].(string); ok {
		mu.Lock()
		accessToken = token
		mu.Unlock()

		log.Printf("Access token successfully retrieved and stored: %s\n", accessToken)
	} else {
		http.Error(w, "Access token not found in response", http.StatusInternalServerError)
		return
	}

	// Return the result as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func getAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	if accessToken == "" {
		http.Error(w, "Access token not set", http.StatusNotFound)
		return
	}

	w.Write([]byte("Access token: " + accessToken))
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/callback", callbackHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/get-token", getAccessTokenHandler)
	

	// Start the server
	fmt.Println("Server is running on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}
