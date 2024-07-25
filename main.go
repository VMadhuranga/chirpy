package main

import "net/http"

func main() {
	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	serveMux.Handle("/app/*", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	serveMux.Handle("assets/logo.png", http.FileServer(http.Dir("./assets/logo.png")))

	// check server readiness
	serveMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
