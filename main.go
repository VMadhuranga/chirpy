package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

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
	apiConfig.jwtSecret = os.Getenv("JWT_SECRET")

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

	serveMux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		pld := payload{}
		err := json.NewDecoder(r.Body).Decode(&pld)
		if err != nil {
			log.Printf("error decoding payload: %s\n", err)
			respondWithError(w, http.StatusBadRequest, "error decoding payload")
			return
		}
		defer r.Body.Close()

		usr, err := apiConfig.queries.GetUserByEmail(r.Context(), pld.Email)
		if err != nil {
			log.Printf("incorrect email: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "incorrect email")
			return
		}

		err = auth.CheckPasswordHash(usr.HashedPassword, pld.Password)
		if err != nil {
			log.Printf("incorrect password: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "incorrect password")
			return
		}

		token, err := auth.MakeJWT(usr.ID, apiConfig.jwtSecret, 1*time.Hour)
		if err != nil {
			log.Printf("error making jwt: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error making jwt")
			return
		}

		rToken, err := auth.MakeRefreshToken()
		if err != nil {
			log.Printf("error making refresh token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error making refresh token")
			return
		}

		_, err = apiConfig.queries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     rToken,
			UserID:    usr.ID,
			ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
		})
		if err != nil {
			log.Printf("error creating refresh token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error creating refresh token")
			return
		}

		respondWithJSON(w, http.StatusOK, loginRes{
			ID:           usr.ID,
			CreatedAt:    usr.CreatedAt,
			UpdatedAt:    usr.UpdatedAt,
			Email:        usr.Email,
			Token:        token,
			RefreshToken: rToken,
		})
	})
	serveMux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("error getting bearer token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error getting bearer token")
			return
		}

		rToken, err := apiConfig.queries.GetRefreshTokenByToken(r.Context(), token)
		if err != nil {
			log.Printf("error getting refresh token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error getting refresh token")
			return
		}

		if rToken.RevokedAt.Valid {
			log.Println("refresh token expired", err)
			respondWithError(w, http.StatusUnauthorized, "refresh token expired")
			return
		}

		aToken, err := auth.MakeJWT(rToken.UserID, apiConfig.jwtSecret, 1*time.Hour)
		if err != nil {
			log.Printf("error making jwt: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error making jwt")
			return
		}

		respondWithJSON(w, http.StatusOK, refreshRes{
			Token: aToken,
		})
	})
	serveMux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("error getting bearer token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error getting bearer token")
			return
		}

		err = apiConfig.queries.RevokeRefreshToken(r.Context(), database.RevokeRefreshTokenParams{
			RevokedAt: sql.NullTime{
				Time:  time.Now(),
				Valid: true,
			},
			UpdatedAt: time.Now(),
			Token:     token,
		})
		if err != nil {
			log.Printf("error revoking token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error revoking token")
			return
		}

		respondWithJSON(w, http.StatusNoContent, nil)
	})

	serveMux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		pld := payload{}
		err := json.NewDecoder(r.Body).Decode(&pld)
		if err != nil {
			log.Printf("error decoding payload: %s\n", err)
			respondWithError(w, http.StatusBadRequest, "error decoding payload")
			return
		}
		defer r.Body.Close()

		hashedPassword, err := auth.HashPassword(pld.Password)
		if err != nil {
			log.Printf("error hashing password: %s\n", err)
			respondWithError(w, http.StatusInternalServerError, "error hashing password")
			return
		}

		usr, err := apiConfig.queries.CreateUser(r.Context(), database.CreateUserParams{
			Email:          pld.Email,
			HashedPassword: hashedPassword,
		})
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
	serveMux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("error getting bearer token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error getting bearer token")
			return
		}

		usrID, err := auth.ValidateJWT(token, apiConfig.jwtSecret)
		if err != nil {
			log.Printf("error validating token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error validating token")
			return
		}

		type payload struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		pld := payload{}
		err = json.NewDecoder(r.Body).Decode(&pld)
		if err != nil {
			log.Printf("error decoding payload: %s\n", err)
			respondWithError(w, http.StatusBadRequest, "error decoding payload")
			return
		}
		defer r.Body.Close()

		hashedPassword, err := auth.HashPassword(pld.Password)
		if err != nil {
			log.Printf("error hashing password: %s\n", err)
			respondWithError(w, http.StatusInternalServerError, "error hashing password")
			return
		}

		usr, err := apiConfig.queries.UpdateUserByID(r.Context(), database.UpdateUserByIDParams{
			Email:          pld.Email,
			HashedPassword: hashedPassword,
			UpdatedAt:      time.Now(),
			ID:             usrID,
		})
		if err != nil {
			log.Printf("error updating user by id: %s", err)
			respondWithError(w, http.StatusInternalServerError, "error updating user by id")
			return
		}

		respondWithJSON(w, http.StatusOK, userRes{
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
	serveMux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("error getting bearer token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error getting bearer token")
			return
		}

		usrID, err := auth.ValidateJWT(token, apiConfig.jwtSecret)
		if err != nil {
			log.Printf("error validating token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error validating token")
			return
		}

		type payload struct {
			Body string `json:"body"`
		}

		pld := payload{}
		err = json.NewDecoder(r.Body).Decode(&pld)
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

	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("error getting bearer token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error getting bearer token")
			return
		}

		usrID, err := auth.ValidateJWT(token, apiConfig.jwtSecret)
		if err != nil {
			log.Printf("error validating token: %s\n", err)
			respondWithError(w, http.StatusUnauthorized, "error validating token")
			return
		}

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

		if chirp.UserID.String() != usrID.String() {
			log.Println("user is not the author of the chirp")
			respondWithError(w, http.StatusForbidden, "user is not the author of the chirp")
			return
		}

		err = apiConfig.queries.DeleteChirpByID(r.Context(), chirp.ID)
		if err != nil {
			log.Printf("error deleting chirp by id: %s", err)
			respondWithError(w, http.StatusInternalServerError, "error deleting chirp by id")
			return
		}

		respondWithJSON(w, http.StatusNoContent, nil)
	})

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
}
