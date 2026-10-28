package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Response struct {
	Status string `json:"status"`
}

type User struct {
	ID           uint
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string
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

func main() {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatalf("failed to connect to the database: %v", err)
	}

	err1 := db.AutoMigrate(&User{})

	if err1 != nil {
		log.Fatalf("error in automigrate: %v", err1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	log.Fatal(http.ListenAndServe(":8080", mux))

}
