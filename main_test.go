package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireAuth_ValidToken(t *testing.T) {
	secret := "test-secret-that-is-long-enough-123"
	tok, err := createToken(secret, User{ID: 1, Email: "a@b.com"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	next := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	requireAuth(secret, next)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireAuth_NoHeader(t *testing.T) {
	secret := "test-secret-that-is-long-enough-123"
	//tok, err := createToken(secret, User{ID: 1, Email: "a@b.com"}, time.Hour)

	next := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	//req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	requireAuth(secret, next)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuth_ExpiredToken(t *testing.T) {
	secret := "test-secret-that-is-long-enough-123"
	tok, err := createToken(secret, User{ID: 1, Email: "a@b.com"}, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	next := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	requireAuth(secret, next)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
