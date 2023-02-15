package main

import (
	"github.com/puneet105/go-csrf-http-jwt/database"
	"github.com/puneet105/go-csrf-http-jwt/server"
	"github.com/puneet105/go-csrf-http-jwt/server/middleware/jwt"
	"log"
)

var host = "localhost"
var port = "9001"

func main(){
	database.InitDB()

	jwtErr := jwt.InitJwt()
	if jwtErr != nil{
		log.Println("error initializing JWT")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil{
		log.Println("error starting server")
		log.Fatal(serverErr)
	}

}


