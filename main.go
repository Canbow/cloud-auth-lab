package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

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

// PageData passes messages back to the UI
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

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./cloud_users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT)`)

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) { authHandler(w, r, true) })
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { authHandler(w, r, false) })

	fmt.Println("Secure UI Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
