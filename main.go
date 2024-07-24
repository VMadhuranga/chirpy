package main

import "net/http"

func main() {
	serveMux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}
	serveMux.Handle("/", http.FileServer(http.Dir(".")))
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
