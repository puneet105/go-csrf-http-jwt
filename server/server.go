package server

import (
	"github.com/puneet105/go-csrf-http-jwt/server/middleware"
	"log"
	"net/http"
)

func StartServer(hostname, port string) error{
	host := hostname + ":" + port
	log.Printf("Listening on %s: ", host)
	handler := middleware.NewHandler()

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}