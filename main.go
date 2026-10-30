package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

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
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

		var maxSizeErr *http.MaxBytesError

		err := json.NewDecoder(r.Body).Decode(&req)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if errors.As(err, &maxSizeErr) {
			log.Printf(".Body byte size is too large: %v", err)
			http.Error(w, "internal server error", http.StatusRequestEntityTooLarge)
			return
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

func main() {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))

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
