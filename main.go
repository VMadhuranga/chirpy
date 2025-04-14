package main

import (
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	queries        *database.Queries
	platform       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) getMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}

type userRes struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

type chirpRes struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) resetMetrics(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)

	if cfg.platform != "dev" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("Hits: %v\n", cfg.fileserverHits.Load())))
		return
	}

	err := cfg.queries.DeleteAllUsers(r.Context())
	if err != nil {
		log.Printf("error deleting all users: %s", err)
		respondWithError(w, http.StatusInternalServerError, "error deleting all users")
		return
	}

	respondWithJSON(w, http.StatusOK, nil)
}

func main() {
	log.SetFlags(log.Lshortfile)

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("error loading env file: %s", err)
	}

	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		log.Fatalf("error opening database: %s", err)
	}
	dbQueries := database.New(db)

	apiConfig := &apiConfig{}
	apiConfig.queries = dbQueries
	apiConfig.platform = os.Getenv("PLATFORM")

	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	serveMux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	serveMux.Handle("assets/logo.png", http.FileServer(http.Dir("./assets/logo.png")))

	serveMux.HandleFunc("GET /admin/metrics", apiConfig.getMetrics)
	serveMux.HandleFunc("POST /admin/reset", apiConfig.resetMetrics)

	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	serveMux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Body   string `json:"body"`
			UserID string `json:"user_id"`
		}

		pld := payload{}
		err := json.NewDecoder(r.Body).Decode(&pld)
		if err != nil {
			log.Printf("error decoding payload: %s\n", err)
			respondWithError(w, http.StatusBadRequest, "error decoding payload")
			return
		}
		defer r.Body.Close()

		if len(pld.Body) > 140 {
			log.Println("payload body is too long")
			respondWithError(w, http.StatusBadRequest, "payload body is too long")
			return
		}

		usrID, err := uuid.Parse(pld.UserID)
		if err != nil {
			log.Printf("error parsing uuid: %s", err)
			respondWithError(w, http.StatusBadRequest, "error parsing uuid")
			return
		}

		chirp, err := apiConfig.queries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   pld.Body,
			UserID: usrID,
		})
		if err != nil {
			log.Printf("error creating chirp: %s", err)
			respondWithError(w, http.StatusInternalServerError, "error creating chirp")
			return
		}

		respondWithJSON(w, http.StatusCreated, chirpRes{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	})
	serveMux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Email string `json:"email"`
		}

		pld := payload{}
		err := json.NewDecoder(r.Body).Decode(&pld)
		if err != nil {
			log.Printf("error decoding payload: %s\n", err)
			respondWithError(w, http.StatusBadRequest, "error decoding payload")
			return
		}
		defer r.Body.Close()

		usr, err := apiConfig.queries.CreateUser(r.Context(), pld.Email)
		if err != nil {
			log.Printf("error creating user: %s\n", err)
			respondWithError(w, http.StatusInternalServerError, "error creating user")
			return
		}

		respondWithJSON(w, http.StatusCreated, userRes{
			ID:        usr.ID,
			CreatedAt: usr.CreatedAt,
			UpdatedAt: usr.UpdatedAt,
			Email:     usr.Email,
		})
	})
	serveMux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirps, err := apiConfig.queries.GetAllChirps(r.Context())
		if err != nil {
			log.Printf("error getting all chirps: %s\n", err)
			respondWithError(w, http.StatusNotFound, "error getting all chirps")
			return
		}

		chirpsRes := []chirpRes{}
		for _, chirp := range chirps {
			chirpsRes = append(chirpsRes, chirpRes(chirp))
		}

		respondWithJSON(w, http.StatusOK, chirpsRes)
	})
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirpID, err := uuid.Parse(r.PathValue("chirpID"))
		if err != nil {
			log.Println("invalid chirp id")
			respondWithError(w, http.StatusBadRequest, "invalid chirp id")
			return
		}

		chirp, err := apiConfig.queries.GetChirpByID(r.Context(), chirpID)
		if err != nil {
			log.Printf("error getting chirp by id: %s", err)
			respondWithError(w, http.StatusNotFound, "error getting chirp by id")
			return
		}

		respondWithJSON(w, http.StatusOK, chirpRes{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	})

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, map[string]string{"error": msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	resData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("error encoding payload: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(resData)
}

func removeProfane(input string) string {
	cleanedInput := strings.Split(input, " ")

	for i, v := range cleanedInput {
		switch strings.ToLower(v) {
		case "kerfuffle", "sharbert", "fornax":
			cleanedInput[i] = "****"
		}
	}

	return strings.Join(cleanedInput, " ")
}
