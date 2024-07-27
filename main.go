package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		metrics := cfg.getMiddlewareMetrics()
		w.Write([]byte(fmt.Sprintf(`
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
		</html>`, metrics)))
	})

	serveMux.HandleFunc("GET /api/reset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		cfg.resetMiddlewareMetrics()
		w.Write([]byte("resettled"))
	})

	serveMux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Body string
		}
		type errorResponse struct {
			Error string `json:"error"`
		}
		type successResponse struct {
			CleanedBody string `json:"cleaned_body"`
		}
		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}
		if len(params.Body) > 140 {
			errRes, err := json.Marshal(errorResponse{
				Error: "Chirp is too long",
			})
			if err != nil {
				log.Printf("Error encoding error response: %s", err)
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write(errRes)
			return
		}
		successRes, err := json.Marshal(successResponse{
			CleanedBody: removeProfane(params.Body),
		})
		if err != nil {
			log.Printf("Error encoding success response: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(successRes)
	})

	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
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
