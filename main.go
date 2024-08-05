package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/VMadhuranga/chirpy/database"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	fileserverHits int
	jwtSecret      string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg apiConfig) getMiddlewareMetrics() int {
	return cfg.fileserverHits
}

func (cfg *apiConfig) resetMiddlewareMetrics() {
	cfg.fileserverHits = 0
}

type userPayload struct {
	Email    string
	Password string
	ExpInSec int `json:"expires_in_seconds"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error loading .env file: %s", err)
		return
	}
	db, err := database.NewDatabase("./")
	if err != nil {
		log.Printf("Error creating database: %s", err)
		return
	}
	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}
	cfg := apiConfig{
		jwtSecret: os.Getenv("JWT_TOKEN"),
	}

	serveMux.Handle("GET /app/*", http.StripPrefix("/app", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	serveMux.Handle("GET /assets/logo.png", http.FileServer(http.Dir("./assets/logo.png")))

	// check server readiness
	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	serveMux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics := cfg.getMiddlewareMetrics()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
		</html>`, metrics)))
	})

	serveMux.HandleFunc("GET /api/reset", func(w http.ResponseWriter, r *http.Request) {
		cfg.resetMiddlewareMetrics()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("resettled"))
	})

	serveMux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")) // get token
		if len(token) == 0 {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		userEmail, err := validateJWT(token)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		u, ok, err := db.GetUser(userEmail)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if !ok {
			respondWithError(w, 404, "User not found")
			return
		}
		type payload struct {
			Body string
		}
		decoder := json.NewDecoder(r.Body)
		pld := payload{}
		err = decoder.Decode(&pld)
		if err != nil {
			log.Printf("Error decoding payload: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if len(pld.Body) > 140 {
			respondWithError(w, 400, "Chirp is too long")
			return
		}
		chirp, err := db.CreateChirp(pld.Body, u.Id)
		if err != nil {
			log.Printf("Error creating chirp: %s", err)
			respondWithError(w, 500, "")
			return
		}
		chirp.Body = removeProfane(chirp.Body)
		chirp.AuthorId = u.Id
		respondWithSuccess(w, 201, chirp)
	})

	serveMux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		authorId := r.URL.Query().Get("author_id")
		sort := r.URL.Query().Get("sort")
		if len(authorId) > 0 {
			authorId, err := strconv.Atoi(authorId)
			if err != nil {
				log.Printf("Error converting string to int: %s", err)
				respondWithError(w, 500, "")
				return
			}
			authorChirps, err := db.GetAuthorChirps(authorId, sort)
			if err != nil {
				log.Printf("Error getting author chirps: %s", err)
				respondWithError(w, 500, "")
				return
			}
			respondWithSuccess(w, 200, authorChirps)
			return
		}
		chirps, err := db.GetChirps(sort)
		if err != nil {
			log.Printf("Error getting chirps: %s", err)
			respondWithError(w, 500, "")
			return
		}
		respondWithSuccess(w, 200, chirps)
	})

	serveMux.HandleFunc("GET /api/chirps/{chirpId}", func(w http.ResponseWriter, r *http.Request) {
		chirpId, err := strconv.Atoi(r.PathValue("chirpId"))
		if err != nil {
			log.Printf("Error converting string to int: %s", err)
			respondWithError(w, 500, "")
			return
		}
		chirp, ok, err := db.GetChirp(chirpId)
		if err != nil {
			log.Printf("Error getting chirp: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if !ok {
			respondWithError(w, 404, "Chirp not found")
			return
		}
		respondWithSuccess(w, 200, chirp)
	})

	serveMux.HandleFunc("DELETE /api/chirps/{chirpId}", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")) // get token
		if len(token) == 0 {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		userEmail, err := validateJWT(token)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		u, ok, err := db.GetUser(userEmail)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if !ok {
			respondWithError(w, 404, "User not found")
			return
		}
		chirpId, err := strconv.Atoi(r.PathValue("chirpId"))
		if err != nil {
			log.Printf("Error converting string to int: %s", err)
			respondWithError(w, 500, "")
			return
		}
		chirp, ok, err := db.GetChirp(chirpId)
		if err != nil {
			log.Printf("Error getting chirp: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if !ok {
			respondWithError(w, 404, "Chirp not found")
			return
		}
		if chirp.AuthorId != u.Id {
			respondWithError(w, 403, "Forbidden")
			return
		}
		err = db.DeleteChirp(chirpId)
		if err != nil {
			log.Printf("Error deleting chirp: %s", err)
			respondWithError(w, 500, "")
			return
		}
		respondWithSuccess(w, 204, nil)
	})

	serveMux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		pld := userPayload{}
		err := decoder.Decode(&pld)
		if err != nil {
			log.Printf("Error decoding payload: %s", err)
			respondWithError(w, 500, "")
			return
		}
		_, ok, err := db.GetUser(pld.Email)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if ok {
			respondWithError(w, 400, "User with this email already exist")
			return
		}
		user, err := db.CreateUser(pld.Email, pld.Password)
		if err != nil {
			log.Printf("Error creating user: %s", err)
			respondWithError(w, 500, "")
			return
		}
		respondWithSuccess(w, 201, user)
	})

	serveMux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		pld := userPayload{}
		err := decoder.Decode(&pld)
		if err != nil {
			log.Printf("Error decoding payload: %s", err)
			respondWithError(w, 500, "")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")) // get token
		if len(token) == 0 {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		userEmail, err := validateJWT(token)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		u, err := db.UpdateUser(userEmail, pld.Email, pld.Password)
		if err != nil {
			log.Printf("Error updating user: %s", err)
			respondWithError(w, 500, "")
			return
		}
		respondWithSuccess(w, 200, u)
	})

	serveMux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		pld := userPayload{}
		err := decoder.Decode(&pld)
		if err != nil {
			log.Printf("Error decoding payload: %s", err)
			respondWithError(w, 500, "")
			return
		}
		user, ok, err := db.GetUser(pld.Email)
		if err != nil {
			log.Printf("Error getting user: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if !ok {
			respondWithError(w, 401, "Incorrect email")
			return
		}
		err = login(user.Password, pld.Password)
		if err != nil {
			respondWithError(w, 401, "Incorrect password")
			return
		}
		jwtExpTime := time.Duration(pld.ExpInSec) * time.Second
		if pld.ExpInSec == 0 || jwtExpTime > 1*time.Hour {
			jwtExpTime = 1 * time.Hour
		}
		accessToken, err := createJWT(jwtExpTime, user.Email, cfg.jwtSecret)
		if err != nil {
			log.Printf("Error creating jwt: %s", err)
			respondWithError(w, 500, "")
			return
		}
		refreshToken, err := db.CreateRefreshToken(pld.Email)
		if err != nil {
			log.Printf("Error creating refresh token: %s", err)
			respondWithError(w, 500, "")
			return
		}
		user.Password = "" // remove password field from response
		user.Token = accessToken
		user.RefreshToken = refreshToken
		respondWithSuccess(w, 200, user)
	})

	serveMux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")) // get token
		if len(token) == 0 {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		u, err := db.GetRefreshTokenUser(token)
		if err != nil {
			log.Printf("Error getting refresh token: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if len(u.RefreshToken) == 0 || u.RefreshTokenExp.Before(time.Now()) {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		token, err = createJWT(1*time.Hour, u.Email, cfg.jwtSecret)
		if err != nil {
			log.Printf("Error creating jwt: %s", err)
			respondWithError(w, 500, "")
			return
		}
		respondWithSuccess(w, 200, struct {
			Token string `json:"token"`
		}{Token: token})
	})

	serveMux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")) // get token
		if len(token) == 0 {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		err := db.RevokeUserRefreshToken(token)
		if err != nil {
			log.Printf("Error revoking refresh token: %s", err)
			respondWithError(w, 500, "")
			return
		}
		respondWithSuccess(w, 204, nil)
	})

	serveMux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "ApiKey")) // get token
		if len(token) == 0 {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		if token != os.Getenv("POLKA_API_KEY") {
			respondWithError(w, 401, "Unauthorized")
			return
		}
		type payload struct {
			Event string `json:"event"`
			Data  struct {
				UserEmail string `json:"user_email"`
			} `json:"data"`
		}
		decoder := json.NewDecoder(r.Body)
		pld := payload{}
		err := decoder.Decode(&pld)
		if err != nil {
			log.Printf("Error decoding payload: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if pld.Event != "user.upgraded" {
			respondWithSuccess(w, 204, nil)
			return
		}
		ok, err := db.UpdateUserChirpyRedStatus(pld.Data.UserEmail)
		if err != nil {
			log.Printf("Error updating chirpy red status: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if !ok {
			respondWithError(w, 404, "User not found")
			return
		}
		respondWithSuccess(w, 204, nil)
	})

	err = server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func login(userPassword, comparingPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(comparingPassword))
}

func createJWT(expTime time.Duration, userEmail, jwtSecret string) (string, error) {
	curTime := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(curTime),
		ExpiresAt: jwt.NewNumericDate(curTime.Add(expTime)),
		Subject:   userEmail,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func validateJWT(token string) (string, error) {
	t, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte{}, nil
	})
	if err != nil {
		return "", err
	}
	sub, err := t.Claims.GetSubject()
	if err != nil {
		return "", err
	}
	return sub, nil
}

func respondWithSuccess(w http.ResponseWriter, statusCode int, payload interface{}) {
	successRes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error encoding success response: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(successRes)
}

func respondWithError(w http.ResponseWriter, statusCode int, errorMessage string) {
	type errorResponse struct {
		Error string `json:"error"`
	}
	if len(errorMessage) == 0 {
		errorMessage = "Internal server error"
	}
	errRes, err := json.Marshal(errorResponse{
		Error: errorMessage,
	})
	if err != nil {
		log.Printf("Error encoding error response: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(errRes)
}

func removeProfane(data string) string {
	profane := map[string]bool{"kerfuffle": true, "sharbert": true, "fornax": true}
	cleanedData := []string{}
	for _, field := range strings.Fields(data) {
		if _, ok := profane[strings.ToLower(field)]; ok {
			cleanedData = append(cleanedData, "****")
		} else {
			cleanedData = append(cleanedData, field)
		}
	}
	return strings.Join(cleanedData, " ")
}
