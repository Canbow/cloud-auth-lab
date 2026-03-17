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
	"golang.org/x/oauth2/github"
)

var (
	db               *sql.DB
	oauthCfg         *oauth2.Config
	oauthStateString = "random-cryptographic-state-string"
)

// Initialize GitHub OAuth Configuration
func initOAuth() {
	oauthCfg = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     "YOUR_GITHUB_CLIENT_ID",     // Paste your GitHub Client ID here
		ClientSecret: "YOUR_GITHUB_CLIENT_SECRET", // Paste your GitHub Client Secret here
		Scopes:       []string{"read:user"},
		Endpoint:     github.Endpoint,
	}
}

// UI Template with GitHub Button
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
        input { width: 100%; padding: 12px 15px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; font-size: 16px; }
        button { width: 100%; padding: 12px; background: #667eea; border: none; border-radius: 8px; color: white; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 10px; }
        button:hover { background: #5a6cd6; }
        
        .divider { display: flex; align-items: center; text-align: center; margin: 20px 0; color: #aaa; font-size: 14px;}
        .divider::before, .divider::after { content: ''; flex: 1; border-bottom: 1px solid #ddd; }
        .divider:not(:empty)::before { margin-right: .5em; }
        .divider:not(:empty)::after { margin-left: .5em; }
        
        /* GitHub Button Styling */
        .github-btn { background: #24292e; color: #fff; border: none; display: flex; align-items: center; justify-content: center; text-decoration: none; border-radius: 8px; font-size: 15px; font-weight: bold; cursor: pointer; transition: background 0.3s; padding: 12px; width: 100%; box-sizing: border-box;}
        .github-btn svg { width: 20px; fill: white; margin-right: 10px; }
        .github-btn:hover { background: #000; }

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
        
        <a href="/login/github" class="github-btn">
            <svg viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
            Continue with GitHub
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

// Local Auth Handler (remains unchanged)
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

// ---------------- GITHUB SSO LOGIC ----------------
func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	url := oauthCfg.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != oauthStateString {
		renderUI(w, PageData{Message: "Invalid state. Possible CSRF attack.", Success: false})
		return
	}

	token, err := oauthCfg.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		renderUI(w, PageData{Message: "Failed to exchange token.", Success: false})
		return
	}

	// Use the authenticated client to fetch the user's GitHub profile
	client := oauthCfg.Client(context.Background(), token)
	response, err := client.Get("https://api.github.com/user")
	if err != nil {
		renderUI(w, PageData{Message: "Failed to get user info.", Success: false})
		return
	}
	defer response.Body.Close()

	var userInfo struct {
		Login string `json:"login"`
	}
	json.NewDecoder(response.Body).Decode(&userInfo)

	// Save the GitHub username in the SQLite database
	db.Exec(`INSERT OR IGNORE INTO users(username, password_hash) VALUES (?, 'GITHUB_SSO')`, userInfo.Login)

	renderUI(w, PageData{Message: fmt.Sprintf("Welcome, %s! Logged in via GitHub.", userInfo.Login), Success: true})
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
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) { authHandler(w, r, true) })
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { authHandler(w, r, false) })

	// GitHub Routes
	http.HandleFunc("/login/github", handleGitHubLogin)
	http.HandleFunc("/callback", handleGitHubCallback)

	fmt.Println("Secure UI Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
