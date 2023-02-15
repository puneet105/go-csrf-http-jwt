package models

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type UserDB struct{
	Username			string	`json:"username"`
	PasswordHash 		string	`json:"password_hash"`
	Role				string	`json:"role"`
}

type Register struct{
	Username string `json:"username"`
	Password string	`json:"password"`
	Role	 string	`json:"role"`
}

type Login struct{
	Username string `json:"username"`
	Password string	`json:"password"`
}

type TokenClaims struct{
	jwt.StandardClaims
	Role	string `json:"role"`
	Csrf	string `json:"csrf"`
}

const (
	RefreshTokenTime = time.Hour * 24
	AuthTokenTime = time.Minute * 15
)

func GenerateCsrfSecret()(string, error){
	byte := make([]byte, 32)
	_, err := rand.Read(byte)
	if err != nil{
		return "", err
	}
	return base64.URLEncoding.EncodeToString(byte), nil
}

