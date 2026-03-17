package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	db               *sql.DB
	oauthCfg         *oauth2.Config
	oauthStateString = "random-cryptographic-state-string" // Protects against CSRF
)

// Initialize Google OAuth Configuration
func initOAuth() {
	oauthCfg = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback", // IMPORTANT: Change to http://YOUR_EC2_IP:8080/callback when deploying
		ClientID:     "YOUR_GOOGLE_CLIENT_ID",          // Get this from Google Cloud Console
		ClientSecret: "YOUR_GOOGLE_CLIENT_SECRET",      // Get this from Google Cloud Console
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

// Updated UI Template with Google Button and Divider
const uiTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Lab | Authentication</title>
    <style>
        body { margin: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; align-items: center; justify-content: center; color: #333; }
        .card { background: rgba(255, 255, 255, 0.95); padding: 40px; border-radius: 15px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 100%; max-width: 400px; text-align: center; }
        h2 { margin-top: 0; color: #4a4a4a; }
        input { width: 100%; padding: 12px 15px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; font-size: 16px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        button { width: 100%; padding: 12px; background: #667eea; border: none; border-radius: 8px; color: white; font-size: 16px; font-weight: bold; cursor: pointer; transition: background 0.3s; margin-top: 10px; }
        button:hover { background: #5a6cd6; }
        
        /* New Styles for Google Button & Divider */
        .divider { display: flex; align-items: center; text-align: center; margin: 20px 0; color: #aaa; font-size: 14px;}
        .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #ddd; }
        .divider:not(:empty)::before { margin-right: .5em; }
        .divider:not(:empty)::after { margin-left: .5em; }
        .google-btn { background: #fff; color: #444; border: 1px solid #ddd; display: flex; align-items: center; justify-content: center; text-decoration: none; border-radius: 8px; font-size: 15px; font-weight: bold; cursor: pointer; transition: background 0.3s; padding: 10px; width: 100%; box-sizing: border-box;}
        .google-btn img { width: 20px; margin-right: 10px; }
        .google-btn:hover { background: #f9f9f9; }

        .message { margin-top: 15px; font-weight: bold; color: #e74c3c; }
        .success { color: #2ecc71; }
        .toggle { margin-top: 20px; font-size: 14px; color: #777; cursor: pointer; }
        .toggle span { color: #667eea; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h2 id="formTitle">Sign In to Cloud</h2>
        
        <form id="authForm" method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" id="submitBtn">Login</button>
        </form>

        <div class="divider">OR</div>
        <a href="/login/google" class="google-btn">
            <img src="https://developers.google.com/identity/images/g-logo.png" alt="Google Logo">
            Continue with Google
        </a>

        {{if .Message}}
            <div class="message {{if .Success}}success{{end}}">{{.Message}}</div>
        {{end}}

        <div class="toggle" onclick="toggleForm()">
            Don't have an account? <span id="toggleText">Sign Up</span>
        </div>
    </div>

    <script>
        let isLogin = true;
        function toggleForm() {
            isLogin = !isLogin;
            document.getElementById('formTitle').innerText = isLogin ? 'Sign In to Cloud' : 'Create an Account';
            document.getElementById('submitBtn').innerText = isLogin ? 'Login' : 'Sign Up';
            document.getElementById('authForm').action = isLogin ? '/login' : '/signup';
            document.getElementById('toggleText').innerText = isLogin ? 'Sign Up' : 'Login';
        }
    </script>
</body>
</html>
`

type PageData struct {
	Message string
	Success bool
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func renderUI(w http.ResponseWriter, data PageData) {
	t, _ := template.New("webpage").Parse(uiTemplate)
	t.Execute(w, data)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderUI(w, PageData{})
}

// ---------------- LOCAL AUTH LOGIC ----------------
func authHandler(w http.ResponseWriter, r *http.Request, isSignup bool) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if isSignup {
		hash, _ := HashPassword(password)
		_, err := db.Exec(`INSERT INTO users(username, password_hash) VALUES (?, ?)`, username, hash)
		if err != nil {
			renderUI(w, PageData{Message: "Username already exists!", Success: false})
			return
		}
		renderUI(w, PageData{Message: "Account created! You can now log in.", Success: true})
	} else {
		var hash string
		err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash)
		if err != nil || !CheckPasswordHash(password, hash) {
			renderUI(w, PageData{Message: "Invalid username or password.", Success: false})
			return
		}
		renderUI(w, PageData{Message: fmt.Sprintf("Welcome back, %s! Authentication successful.", username), Success: true})
	}
}

// ---------------- GOOGLE SSO LOGIC ----------------
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := oauthCfg.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state string to prevent cross-site request forgery
	if r.FormValue("state") != oauthStateString {
		renderUI(w, PageData{Message: "Invalid state. Possible CSRF attack.", Success: false})
		return
	}

	// Exchange the Authorization Code for an Access Token
	token, err := oauthCfg.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		renderUI(w, PageData{Message: "Failed to exchange token.", Success: false})
		return
	}

	// Use token to fetch user email from Google APIs
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		renderUI(w, PageData{Message: "Failed to get user info.", Success: false})
		return
	}
	defer response.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	json.NewDecoder(response.Body).Decode(&userInfo)

	// Save the Google user in the SQLite database (using INSERT OR IGNORE so it doesn't fail if they already exist)
	// We insert 'GOOGLE_SSO' instead of a password hash since they don't have a local password.
	db.Exec(`INSERT OR IGNORE INTO users(username, password_hash) VALUES (?, 'GOOGLE_SSO')`, userInfo.Email)

	renderUI(w, PageData{Message: fmt.Sprintf("Welcome, %s! Logged in via Google.", userInfo.Email), Success: true})
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./cloud_users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT)`)

	initOAuth()

	http.HandleFunc("/", indexHandler)

	// Local Routes
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) { authHandler(w, r, true) })
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { authHandler(w, r, false) })

	// Google Routes
	http.HandleFunc("/login/google", handleGoogleLogin)
	http.HandleFunc("/callback", handleGoogleCallback)

	fmt.Println("Secure UI Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
