package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

var jwtKey = []byte("secret_key")
var db *sql.DB

func main() {
	fmt.Println("Starting Chainview API...")

	// Connect to DB
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	hostName := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, hostName, dbPort, dbName)
	if dsn == "" {
		log.Fatal("DB_URL not set")
	}

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal("Error opening DB:", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging DB:", err)
	}
	fmt.Println("Successfully connected to DB")

	// Start HTTP server
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	// SIGNUP USER
	http.HandleFunc("/signup", signupHandler)

	// LOGIN USER
	http.HandleFunc("/login", loginHandler)

	// GET USERS
	http.HandleFunc("/users", authMiddleware(getAllUsersHandler))

	// GET WALLET DETAILS
	http.HandleFunc("/wallet", authMiddleware(getWalletDetails))

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
	})
	handler := c.Handler(http.DefaultServeMux)
	fmt.Println("Server listening on port 3000")
	err = http.ListenAndServe(":3000", handler)

	if err != nil {
		log.Fatal("Server Error: ", err)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func getWalletDetails(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "No address provided", http.StatusBadRequest)
		return
	}

	// Get Balance from Etherscan
	apiKey := os.Getenv("ETHERSCAN_API_KEY")
	fmt.Println("API key", apiKey)
	url := fmt.Sprintf("https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address=%s&tag=latest&apikey=%s", address, apiKey)
	//url := fmt.Sprintf("https://api.covalenthq.com/v1/1/address/%s/balances_v2/", address)
	fmt.Println("Url Balance", url)

	res, err := http.Get(url)
	if err != nil {
		http.Error(w, "Failed to fetch from EtherScan", http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		http.Error(w, "Failed reading response body", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type Credentials struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}

	// Check for existing user unique email
	var exists int
	err = db.QueryRow("SELECT COUNT(1) FROM chainview.users WHERE email = $1", cred.Email).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists > 0 {
		http.Error(w, "Email already in use", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(cred.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Insert user
	userID := uuid.New().String()

	_, err = db.Exec("INSERT INTO chainview.users (id, name, email, password) VALUES ($1, $2, $3, $4)", userID, cred.Username, cred.Email, string(hashedPwd))
	if err != nil {
		fmt.Println("Errror sql", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User created successfully!"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse login json body
	type Credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get user from DB
	var storedHashedPwd string
	var userID string
	err = db.QueryRow("SELECT id, password FROM chainview.users WHERE email = $1", cred.Email).Scan(&userID, &storedHashedPwd)
	if err != nil {
		http.Error(w, "Failed to query user", http.StatusUnauthorized)
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPwd), []byte(cred.Password))
	if err != nil {
		fmt.Println("Incorrect password", err)
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	// Respond with token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func getAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, email FROM chainview.users")
	if err != nil {
		http.Error(w, "Failed to query users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err = rows.Scan(&user.ID, &user.Name, &user.Email)
		if err != nil {
			log.Printf("Error scanning row: %s\n", err)
			http.Error(w, "Failed dfsasd user", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}
