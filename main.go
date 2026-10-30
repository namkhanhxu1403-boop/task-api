package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Response struct {
	Status string `json:"status"`
}

type User struct {
	ID           uint
	Email        string `gorm:"uniqueIndex; not null"`
	PasswordHash string
}

type userSend struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type customClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type signedTokenJSON struct {
	Token string `json:"token"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sta := Response{Status: "ok"}

	err := json.NewEncoder(w).Encode(sta)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

var emailFormatComparison = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9._%+-]+\.[A-Za-z]{2,}$`)

func registerHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerRequest
		r.Body = http.MaxBytesReader(w, r.Body, 1<<8)

		var maxSizeErr *http.MaxBytesError

		err := json.NewDecoder(r.Body).Decode(&req)

		if err != nil {
			if errors.As(err, &maxSizeErr) {
				log.Printf("request .body is too large: %v", err)
				http.Error(w, "internal server error", http.StatusRequestEntityTooLarge)
				return
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if req.Email == "" || len(req.Email) > 254 || len(req.Password) < 8 || len(req.Password) > 72 {
			http.Error(w, "Password or email did not matched the requirement. Try again.", http.StatusBadRequest)
			return
		}

		processedEmail := strings.ToLower(strings.TrimSpace(req.Email))

		if !emailFormatComparison.MatchString(processedEmail) {
			http.Error(w, "Wrong email format. Try again.", http.StatusBadRequest)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Something went wrong when hashing the password: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		var user = User{Email: processedEmail, PasswordHash: string(hash)}

		result := db.Create(&user)

		if result.Error != nil {

			if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
				http.Error(w, "Error duplicated email. Try another email.", http.StatusConflict)
				return
			}
			log.Printf("something went wrong when creating the database : %v", result.Error)
			http.Error(w, "internal database error", http.StatusInternalServerError)
			return
		}

		usersend := userSend{ID: user.ID, Email: user.Email}

		w.Header().Set("Content-Type", "application/json")

		w.WriteHeader(http.StatusCreated)

		json.NewEncoder(w).Encode(usersend)

	}
}

func loginHandler(db *gorm.DB, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerRequest

		r.Body = http.MaxBytesReader(w, r.Body, 1<<8)
		var maxSizeErr *http.MaxBytesError

		err := json.NewDecoder(r.Body).Decode(&req)

		if err != nil {
			if errors.As(err, &maxSizeErr) {
				log.Printf("request .body is too large: %v", err)
				http.Error(w, "internal server error", http.StatusRequestEntityTooLarge)
				return
			} else {
				log.Printf("%v", err)
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
		}

		if req.Email == "" || req.Password == "" {
			http.Error(w, "did not enter enough information (either email or password)", http.StatusBadRequest)
			return
		}

		processedEmail := strings.ToLower(strings.TrimSpace(req.Email))

		var user User
		result := db.Where("email = ?", processedEmail).First(&user)

		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				http.Error(w, "invalid email or password", http.StatusUnauthorized)
				return
			} else {
				log.Printf("unexpected database error: %v", result.Error)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
			http.Error(w, "invalid email or password", http.StatusUnauthorized)
			return
		}

		claims := customClaims{
			Email: processedEmail,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "task-api",
				Subject:   strconv.Itoa(int(user.ID)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		signedToken, err := token.SignedString([]byte(secret))

		if err != nil {
			log.Printf("error when signing token: %v", err)
			http.Error(w, "error when signing token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		w.WriteHeader(http.StatusOK)

		resultSignedToken := signedTokenJSON{Token: signedToken}

		json.NewEncoder(w).Encode(resultSignedToken)
	}
}

func main() {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))
	secret := os.Getenv("JWT_SECRET")

	if secret == "" {
		log.Fatal("no secret key")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		TranslateError: true,
	})

	if err != nil {
		log.Fatalf("failed to connect to the database: %v", err)
	}

	err1 := db.AutoMigrate(&User{})

	if err1 != nil {
		log.Fatalf("error in automigrate: %v", err1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", registerHandler(db))
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("POST /login", loginHandler(db, secret))
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
	//or log.Fatal(mux.ListenAndServe(":8080", mux)) to ignore the timeout
}
