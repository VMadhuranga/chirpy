package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

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
