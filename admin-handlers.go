package main

import (
	"fmt"
	"log"
	"net/http"
)

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
