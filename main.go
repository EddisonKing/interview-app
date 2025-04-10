package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/golang-jwt/jwt/v5"
	uuid "github.com/satori/go.uuid"
)

var db *sql.DB

var jwtKey = []byte("a_really_long_secret_that_should_not_be_commited_to_source_control")

const port = 8080

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Note struct {
	ID      string `json:"id"`
	UserID  int    `json:"user_id"`
	Content string `json:"content"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./app.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err = DBMigrations(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/notes", handleNotes)
	http.HandleFunc("/note/{note_id}", handleViewNote)

	fmt.Printf("Listening :%d...\n", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatal(err)
	}
}

func DBMigrations() error {
	usersQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);

	INSERT OR IGNORE INTO users (id, username, password) VALUES (
	  1,
		'admin',
		'4a55f0a4098d27e1ffdc5f91ae9d8a281d3d99a30ad3ef2f9a6660b34b9e183d'
	);
	`

	notesQuery := `
	CREATE TABLE IF NOT EXISTS notes (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);
	`
	if _, err := db.Exec(usersQuery); err != nil {
		return err
	}
	_, err := db.Exec(notesQuery)
	return err
}

func handleRoot(res http.ResponseWriter, _ *http.Request) {
	html := `<html>
	<head><title>Secure'ish Notes</title></head>
	<body>
	<h1>Secure'ish Notes</h1>
	Welcome to a secure (we promise) notes API.
	<h2>API Spec</h2>
	<h3>Register</h3>
	<code>curl -X POST <a class="api_link">register</a> -d '{"username":"NEW_USERNAME","password":"NEW_PASSWORD"}'</code>
	<h3>Login</h3>
	<code>curl -X POST <a class="api_link">login</a> -d '{"username":"USERNAME","password":"PASSWORD"}'</code>
	<h3>Notes</h3>
	<h4>List</h4>
	<code>curl -X GET <a class="api_link">notes</a> -H 'Authorization: Bearer {{BEARER_TOKEN}}'</code>
	<h4>Create</h4>
	<code>curl -X POST <a class="api_link">notes</a> -H 'Authorization: Bearer {{BEARER_TOKEN}}' -d '{"content":"NOTE_CONTENT"}'</code>
	<h4>View</h4>
	<code>curl -X GET <a class="api_link">note/{NOTE_ID}</a></code>
	</body>
	<script>
		var baseUrl = document.location.href;
		console.dir(baseUrl);
		var apiLinks = document.getElementsByClassName('api_link');
		console.dir(apiLinks);
		for(let i = 0; i < apiLinks.length; i++) {
			let target = baseUrl + apiLinks[i].innerText;
			console.dir(target);
			apiLinks[i].href = target;
			apiLinks[i].innerText = target;
			console.dir(apiLinks[i]);
		}
	</script>
	</html>`
	fmt.Fprint(res, html)
}

func handleRegister(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(res, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var user User
	if err := json.NewDecoder(req.Body).Decode(&user); err != nil {
		http.Error(res, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedPassword := sha256.Sum256([]byte(user.Password))
	user.Password = hex.EncodeToString(hashedPassword[:])

	if user.Password == "" {
		http.Error(res, "Password cannot be empty", http.StatusBadRequest)
		return
	}

	if user.Username == "" {
		http.Error(res, "Username cannot be empty", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, user.Password)
	if err != nil {
		http.Error(res, fmt.Sprintf("Error inserting user: %v", err), http.StatusInternalServerError)
		return
	}
	id, _ := result.LastInsertId()
	user.ID = int(id)
	user.Password = "**********"
	res.Header().Set("Content-Type", "application/json")
	json.NewEncoder(res).Encode(user)
}

func handleLogin(res http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		handleLoginAttempt(res, req)
	case http.MethodGet:
		handleLoginPage(res, req)
	default:
		http.Error(res, fmt.Sprintf("Method %s not allowed, only supporting GET and POST", req.Method), http.StatusMethodNotAllowed)
		return
	}
}

func handleLoginPage(res http.ResponseWriter, _ *http.Request) {
	html := `<html>
	<body>
	<p>Login via this same endpoint using a POST request containing a body of:
			</br>
			<pre><code>{
	"username": "YOUR_USERNAME",
	"password": "YOUR_PASSWORD"
}</code></pre>
		</p>
	</body>
	</html>`
	fmt.Fprint(res, html)
}

func handleLoginAttempt(res http.ResponseWriter, req *http.Request) {
	var creds User
	if err := json.NewDecoder(req.Body).Decode(&creds); err != nil {
		http.Error(res, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedPassword := sha256.Sum256([]byte(creds.Password))
	hashed := hex.EncodeToString(hashedPassword[:])

	var user User
	query := fmt.Sprintf("SELECT id, username, password FROM users WHERE username = '%s' and password = '%s'", creds.Username, hashed)
	err := db.QueryRow(query).
		Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		http.Error(res, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := jwt.NewNumericDate(time.Now().Add(72 * time.Hour))
	claims := &Claims{
		user.Username,
		jwt.RegisteredClaims{
			ExpiresAt: expirationTime,
			Subject:   user.Username,
			ID:        fmt.Sprintf("%d", user.ID),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(res, "Error generating token", http.StatusInternalServerError)
		return
	}
	res.Header().Set("Content-Type", "application/json")
	json.NewEncoder(res).Encode(map[string]string{"token": tokenString})
}

func authorize(res http.ResponseWriter, req *http.Request) (*Claims, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		errMsg := "Missing Authorization Header"
		http.Error(res, errMsg, http.StatusUnauthorized)
		return nil, errors.New(errMsg)
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		errMsg := "Invalid Authorization Header Format"
		http.Error(res, errMsg, http.StatusUnauthorized)
		return nil, errors.New(errMsg)
	}
	tokenStr := parts[1]
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		errMsg := "Invalid token"
		http.Error(res, errMsg, http.StatusUnauthorized)
		return nil, fmt.Errorf(errMsg)
	}

	return claims, nil
}

func handleViewNote(res http.ResponseWriter, req *http.Request) {
	note := &Note{}
	err := db.QueryRow("SELECT id, content, user_id FROM notes WHERE id = ?", req.PathValue("note_id")).Scan(&note.ID, &note.Content, &note.UserID)
	if err != nil {
		http.Error(res, "Note not found", http.StatusNotFound)
		return
	}

	html := `
	<html>
	<head><title>Secure'ish Notes</title></head>
	<body>
	<h1>Note %s:</h1>
	<p>%s</p>
	</body>
	</html>
	`
	fmt.Fprintf(res, html, note.ID, note.Content)
}

func handleNotes(res http.ResponseWriter, req *http.Request) {
	claims, err := authorize(res, req)
	if err != nil {
		return
	}

	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", claims.Username).Scan(&userID)
	if err != nil {
		http.Error(res, "User not found", http.StatusUnauthorized)
		return
	}

	switch req.Method {
	case http.MethodPost:
		createNoteHandler(res, req, userID)
	case http.MethodGet:
		listNotesHandler(res, req, userID)
	default:
		http.Error(res, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func createNoteHandler(res http.ResponseWriter, req *http.Request, userID int) {
	var noteData struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(req.Body).Decode(&noteData); err != nil {
		http.Error(res, "Invalid request", http.StatusBadRequest)
		return
	}
	noteUUID := uuid.NewV4()
	noteID := noteUUID.String()

	_, err := db.Exec("INSERT INTO notes (id, user_id, content) VALUES (?, ?, ?)", noteID, userID, noteData.Content)
	if err != nil {
		http.Error(res, fmt.Sprintf("Error creating note: %v", err), http.StatusInternalServerError)
		return
	}

	note := Note{
		ID:      noteID,
		UserID:  userID,
		Content: noteData.Content,
	}
	res.Header().Set("Content-Type", "application/json")
	json.NewEncoder(res).Encode(note)
}

func listNotesHandler(res http.ResponseWriter, req *http.Request, userID int) {
	rows, err := db.Query("SELECT id, content FROM notes WHERE user_id = ?", userID)
	if err != nil {
		http.Error(res, "Error fetching notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	notes := make([]Note, 0)
	for rows.Next() {
		var note Note
		note.UserID = userID
		if err := rows.Scan(&note.ID, &note.Content); err != nil {
			http.Error(res, "Error scanning note", http.StatusInternalServerError)
			return
		}
		notes = append(notes, note)
	}
	res.Header().Set("Content-Type", "application/json")
	json.NewEncoder(res).Encode(notes)
}
