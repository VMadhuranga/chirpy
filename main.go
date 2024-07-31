package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/VMadhuranga/chirpy/database"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	fileserverHits int
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

func main() {
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
	cfg := apiConfig{}

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
		type payload struct {
			Body string
		}
		decoder := json.NewDecoder(r.Body)
		pld := payload{}
		err := decoder.Decode(&pld)
		if err != nil {
			log.Printf("Error decoding payload: %s", err)
			respondWithError(w, 500, "")
			return
		}
		if len(pld.Body) > 140 {
			respondWithError(w, 400, "Chirp is too long")
			return
		}
		chirp, err := db.CreateChirp(pld.Body)
		if err != nil {
			log.Printf("Error creating chirp: %s", err)
			respondWithError(w, 500, "")
			return
		}
		chirp.Body = removeProfane(chirp.Body)
		respondWithSuccess(w, 201, chirp)
	})

	serveMux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirps, err := db.GetChirps()
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

	serveMux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Email    string
			Password string
		}
		decoder := json.NewDecoder(r.Body)
		pld := payload{}
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

	serveMux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Email    string
			Password string
		}
		decoder := json.NewDecoder(r.Body)
		pld := payload{}
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
		user.Password = ""
		respondWithSuccess(w, 201, user)
	})

	err = server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func login(userPassword, comparingPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(comparingPassword))
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
