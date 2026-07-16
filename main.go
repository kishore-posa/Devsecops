package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var dbPool *pgxpool.Pool

//2026_Architect_Ultra_Secret_Signing_Key_Do_Not_Leak
var jwtSecretKey []byte

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type APIResponse struct {
	Message string `json:"message"`
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func main() {
	ctx := context.Background()
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://secure_admin:SuperSecretPassword2026!@localhost:5432/user_store"
	}

	secretEnv := os.Getenv("JWT_SECRET")
	if secretEnv != "" {
		jwtSecretKey = []byte(secretEnv)
	} else {
		jwtSecretKey = []byte("2026_Architect_Ultra_Secret_Signing_Key_Do_Not_Leak")
	}

	var err error
	dbPool, err = pgxpool.New(ctx, connStr)

	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer dbPool.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/register", handleRegister)
	mux.HandleFunc("POST /api/login", handleLogin)

	mux.Handle("GET /api/dashboard", authMiddleware(http.HandlerFunc(handleDashboard)))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Println("Secure API Engine listening on http://localhost:8080...")
	log.Fatal(server.ListenAndServe())
}

func handleRegister(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req RegisterRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Message: "Invalid JSON format or payload too large"})
		return
	}

	if req.Email == "" || len(req.Password) < 8 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Message: "Valid email and a minimum 8-character password required"})
		return
	}

	hashedPassword, err := hashPassword(req.Password)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Message: "Internal processing error"})
		return
	}

	insertSQL := `INSERT INTO users (email, password_hash) VALUES ($1, $2);`

	_, err = dbPool.Exec(context.Background(), insertSQL, req.Email, hashedPassword)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(APIResponse{Message: "Email configuration already registered"})
			return
		}

		log.Printf("Internal DB Error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Message: "An unexpected error occured."})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(APIResponse{Message: "User account established securely."})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var databasePasswordHash string
	var userID int

	query := `SELECT id, password_hash FROM users WHERE email = $1;`
	err := dbPool.QueryRow(context.Background(), query, req.Email).Scan(&userID, &databasePasswordHash)

	log.Printf("[DATABASE ERROR] Query failed for %s: %v", req.Email, err)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid login credentials"})
			return
		}
		log.Printf("[DATABASE ERROR] Query failed for %s: %v", req.Email, err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal server error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(databasePasswordHash), []byte(req.Password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid login credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
		"iat": time.Now().Unix(),
	})

	tokenString, err := token.SignedString(jwtSecretKey)
	log.Printf("[DATABASE ERROR] signed error for %s: %v", req.Email, err)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing or malformed access token"})
			return
		}

		tokenString := authHeader[7:]

		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or expired access token"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"secure_data": "Welcome to the cloud system cockpit. Your authentication signature is valid",
	})
}
