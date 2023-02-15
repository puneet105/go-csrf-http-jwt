package jwt

import(
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/puneet105/go-csrf-http-jwt/database"
	"github.com/puneet105/go-csrf-http-jwt/database/models"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const(
	privateKeyPath = "keys/app.rsa"
	publicKetPath = "keys/app.rsa.pub"
)
var (
	privKey *rsa.PrivateKey
	pubKey *rsa.PublicKey
)

//openssl command to generate public and private .pem encoded keys
//openssl genrsa -out private.pem 2048 && cp private.pem keys/app.rsa
//openssl rsa -in private.pem -pubout -out public.pem && cp public.pem keys/app.rsa.pub

func InitJwt() error{
	privBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil{
		return err
	}

	privKey, err = jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil{
		return err
	}

	pubBytes, err1 := ioutil.ReadFile(publicKetPath)
	if err1 != nil{
		return err1
	}

	pubKey, err1 = jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err1 != nil{
		return err1
	}

	log.Println("Successfully completed InitJwt function")
	return nil

}

func CreateNewTokens(uuid, role string)(authTokenString, refreshTokenString, csrfSecret string, err error){
	//generate csrf secret
	csrfSecret, err = models.GenerateCsrfSecret()
	if err != nil{
		return "","","", err
	}

	//generate refresh token
	refreshTokenString, err = CreateRefreshTokenString(uuid, role, csrfSecret)
	if err != nil{
		return "","","", err
	}

	//generate auth token
	authTokenString, err = CreateAuthTokenString(uuid, role, csrfSecret)
	if err != nil{
		return "","","", err
	}
	return authTokenString, refreshTokenString, csrfSecret, nil
}

func CheckAndRefreshTokens(oldAuthToken, oldRefreshToken, oldCsrfSecret string)(string,string,string,error){
	if oldCsrfSecret == ""{
		log.Println("No Csrf Token")
		err := errors.New("Unauthorized")
		return "","","",err
	}
	authToken, err := jwt.ParseWithClaims(oldAuthToken, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return pubKey, nil
	})
	if err != nil{
		log.Println("Error parsing token with claims")
		return "","","",err
	}
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok{
		return "","","",err
	}
	if oldCsrfSecret != authTokenClaims.Csrf{
		log.Println("CSRF token does not match with jwt!!")
		err := errors.New("Unauthorized")
		return "","","",err
	}

	if authToken.Valid{
		log.Println("Auth Token is valid")
		newCsrfSecret := authTokenClaims.Csrf
		newAuthToken := oldAuthToken
		newRefreshToken, _ := UpdateRefreshTokenExpiry(oldRefreshToken)
		return newAuthToken, newRefreshToken, newCsrfSecret, nil
	}else if ve, ok := err.(*jwt.ValidationError); ok{
		log.Println("Auth Token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0{
			log.Println("Auth Token is expired")
			newAuthToken, newCsrfSecret, err := UpdateAuthTokenString(oldRefreshToken, oldAuthToken)
			if err!= nil{
				return "","","",err
			}
			newRefreshToken, err := UpdateRefreshTokenExpiry(oldRefreshToken)
			if err != nil{
				return "","","",err
			}
			newRefreshToken, err = UpdateRefreshTokenJti(oldRefreshToken)
			if err != nil{
				return "","","",err
			}
			newRefreshToken, _ = UpdateRefreshTokenCsrf(newRefreshToken, newCsrfSecret)
			return newAuthToken, newRefreshToken, newCsrfSecret, nil
		}else{
			log.Println("error in auth token")
			err := errors.New("error is auth token")
			return "","","",err
		}
	}else{
		log.Println("error in auth token")
		err := errors.New("error is auth token")
		return "","","",err
	}

}

func CreateAuthTokenString(uuid, role, csrfSecret string)(authTokenString string, err error){
	authTokenExp := time.Now().Add(models.AuthTokenTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject: uuid,
			ExpiresAt: authTokenExp,
		},
		role,
		csrfSecret,
	}

	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, _ = authJwt.SignedString(privKey)
	return authTokenString, nil
}

func CreateRefreshTokenString(uuid, role, csrfSecret string)(refreshTokenString string, err error){
	refreshTokenExp := time.Now().Add(models.RefreshTokenTime).Unix()
	refreshJti, err := database.StoreRefreshToken()
	if err != nil{
		return
	}
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id: refreshJti,
			Subject: uuid,
			ExpiresAt: refreshTokenExp,
		},
		role,
		csrfSecret,
	}
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, _ = refreshJwt.SignedString(privKey)
	return refreshTokenString, nil
}

func UpdateRefreshTokenExpiry(oldRefreshTokenString string)(string, error){
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return pubKey, nil
	})
	if err != nil{
		log.Println("Error parsing token with claims")
		return "",err
	}
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok{
		return "", errors.New("error parsing oldRefreshTokenClaims")
	}
	refreshTokenExp := time.Now().Add(models.RefreshTokenTime).Unix()
	present := database.CheckRefreshToken(oldRefreshTokenClaims.StandardClaims.Id)
	var refreshClaims models.TokenClaims
	 if !present{
		 newJti, _ := database.StoreRefreshToken()
		 refreshClaims = models.TokenClaims{
			 jwt.StandardClaims{
				 Id: newJti,
				 Subject: oldRefreshTokenClaims.StandardClaims.Subject,
				 ExpiresAt: refreshTokenExp,
			 },
			 oldRefreshTokenClaims.Role,
			 oldRefreshTokenClaims.Csrf,
		 }
	 }else {
		 refreshClaims = models.TokenClaims{
			 jwt.StandardClaims{
				 Id:        oldRefreshTokenClaims.StandardClaims.Id,
				 Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
				 ExpiresAt: refreshTokenExp,
			 },
			 oldRefreshTokenClaims.Role,
			 oldRefreshTokenClaims.Csrf,
		 }
	 }
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err := refreshJwt.SignedString(privKey)
	if err != nil{
		return "", err
	}
	return newRefreshTokenString, nil
}

func UpdateRefreshTokenJti(oldRefreshTokenString string)(string,error){
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return pubKey, nil
	})
	if err != nil{
		log.Println("Error parsing token with claims")
		return "",err
	}
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok{
		return "", errors.New("error parsing oldRefreshTokenClaims")
	}
	refreshJti, err := database.StoreRefreshToken()
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id: refreshJti,
			Subject: oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
		oldRefreshTokenClaims.Role,
		oldRefreshTokenClaims.Csrf,
	}
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err := refreshJwt.SignedString(privKey)
	if err != nil{
		return "", err
	}
	return newRefreshTokenString, nil
}

func UpdateAuthTokenString(oldRefreshToken, oldAuthToken string)(string, string, error){
	refreshToken, _ := jwt.ParseWithClaims(oldRefreshToken, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error){
		return pubKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok{
		err := errors.New("error reading jwt claims")
		return "","",err
	}
	if database.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id){
		if refreshToken.Valid{
			authToken, _ := jwt.ParseWithClaims(oldAuthToken, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return pubKey, nil
			})
			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok{
				err := errors.New("error reading jwt claims")
				return "","",err
			}

			csrfSecret ,err := models.GenerateCsrfSecret()
			if err != nil{
				return "","",err
			}
			newAuthTokenString, err := CreateAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
			return newAuthTokenString, csrfSecret, nil

		}else{
			log.Println("refresh token is expired")
			database.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)
			err := errors.New("unauthorized")
			return "","",err
		}
	}else{
		log.Println("refresh token has been revoked")
		err := errors.New("unauthorized")
		return "","",err
	}
}

func RevokeRefreshToken(w *http.ResponseWriter, refreshTokenString string)(string, bool, error){
	//use refresh token string to get refresh token
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil{
		return "",true,errors.New("could not parse token with claims")
	}

	//use refresh token to get refresh token claims
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok{
		return "",true,errors.New("could not read refresh token claims")
	}

	//delete refresh token using method in database
	log.Println("Deleting refresh token for uuid : ", refreshTokenClaims.Subject)
	log.Println("refreshTokenClaims.StandardClaims.Id is :",refreshTokenClaims.StandardClaims.Id)
	present := database.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id)
	if present{
		database.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)
	}else{
		return "",false, nil
	}


	return refreshTokenClaims.Subject,true, nil
}

func UpdateRefreshTokenCsrf(oldRefreshToken, newCsrfSecret string)(string, error){
	refreshToken, _ := jwt.ParseWithClaims(oldRefreshToken, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok{
		return "",errors.New("error parsing oldRefreshTokenClaims")
	}


	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id: oldRefreshTokenClaims.StandardClaims.Id,
			Subject: oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
		oldRefreshTokenClaims.Role,
		newCsrfSecret,
	}
	newRefreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, _ := newRefreshJwt.SignedString(privKey)
	return newRefreshTokenString, nil
}

func FetchUUID(authTokenString string)(string, error){
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("error fetching claims")
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok{
		return "", errors.New("error fetching claims")
	}
	return authTokenClaims.StandardClaims.Subject, nil
}
