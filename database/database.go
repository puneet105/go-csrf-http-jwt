package database

import (
	"errors"
	"github.com/google/uuid"
	"github.com/puneet105/go-csrf-http-jwt/database/models"
	"golang.org/x/crypto/bcrypt"
	"log"
)

var Users = map[string]models.UserDB{}
var refreshTokens  map[string]string
func InitDB(){
	refreshTokens = make(map[string]string)
	log.Println("Successfully completed InitDB function")
}

func StoreUser(username, password, role string)(string,error){
	uuID := uuid.New()

	user := models.UserDB{}
	for user != Users[uuID.String()]{
		uuID = uuid.New()
	}

	hashPassword, hashErr := GenerateBcryptHash(password)
	if hashErr != nil{
		err := hashErr
		return "", err
	}
	Users[uuID.String()] = models.UserDB{
		Username:    username,
		PasswordHash: hashPassword,
		Role:         role,
	}
	log.Printf("From StoreUser function entries in DB are: %+v", Users)
	return uuID.String(), nil
}

func DeleteUser(uuid string)(models.UserDB, error){
	log.Printf("From delete user from db function, pre entries: %+v", Users)
	delete(Users, uuid)
	log.Printf("From delete user from db function, post entries: %+v", Users)
	return Users[uuid], nil
}

func FetchUserById(uuid string)(models.UserDB, error){
	user := Users[uuid]
	emptyUser := models.UserDB{}
	if emptyUser != user{
		return user,nil
	}else{
		return models.UserDB{}, errors.New("user not found that matches given uuid")
	}
}

func FetchUserByUsername(username string)(models.UserDB, string, error) {
	for uuid, val := range Users {
		if val.Username == username{
			return val, uuid, nil
			break
		}
	}
	return models.UserDB{}, "", errors.New("User not found...!!")
}


func StoreRefreshToken()(string,error){
	jti := uuid.New()
	for refreshTokens[jti.String()] != ""{
		jti = uuid.New()
	}
	refreshTokens[jti.String()] = "valid"
	log.Printf("From store refresh token function, entries are : %+v",refreshTokens)
	return jti.String(), nil
}

func DeleteRefreshToken(jti string){
	log.Printf("From Delete refresh token function, pre delete entries :%+v",refreshTokens)
	delete(refreshTokens, jti)
	log.Printf("From Delete refresh token function, post delete entries :%+v",refreshTokens)
}

func CheckRefreshToken(jti string)bool{
	return refreshTokens[jti] != ""
}

func LogUserIn(username, password string)(models.UserDB,string,error){
	user, uuid, userErr := FetchUserByUsername(username)
	if userErr != nil{
		return models.UserDB{},"",userErr
	}
	return user, uuid, CheckPasswordAgainstHash(user.PasswordHash, password)
}

func GenerateBcryptHash(password string)(string , error){
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func CheckPasswordAgainstHash(hashPassword, password string)error{
	return bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))
}

