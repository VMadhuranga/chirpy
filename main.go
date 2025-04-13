package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
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

func (cfg *apiConfig) resetMetrics(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hits: %v\n", cfg.fileserverHits.Load())))
}

func main() {
	log.SetFlags(log.Lshortfile)

	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}
	apiConfig := &apiConfig{}

	serveMux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	serveMux.Handle("assets/logo.png", http.FileServer(http.Dir("./assets/logo.png")))

	serveMux.HandleFunc("GET /admin/metrics", apiConfig.getMetrics)
	serveMux.HandleFunc("POST /admin/reset", apiConfig.resetMetrics)

	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	serveMux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		type payload struct {
			Body string `json:"body"`
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
			log.Printf("payload body is too long\n")
			respondWithError(w, http.StatusBadRequest, "payload body is too long")
			return
		}

		type successResponse struct {
			CleanedBody string `json:"cleaned_body"`
		}
		respondWithJSON(w, http.StatusOK, successResponse{
			CleanedBody: removeProfane(pld.Body),
		})
	})

	err := server.ListenAndServe()
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
