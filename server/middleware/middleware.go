package middleware

import (
	"encoding/json"
	"fmt"
	"github.com/justinas/alice"
	"github.com/puneet105/go-csrf-http-jwt/database"
	"github.com/puneet105/go-csrf-http-jwt/database/models"
	"github.com/puneet105/go-csrf-http-jwt/server/middleware/jwt"
	"log"
	"net/http"
	"time"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panicf("Recovered From Panic! : %+v", err)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

func authHandler(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login", "/logout", "/deleteUser":
			log.Println("In Auth Handler Section")
			authCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No Auth Cookie")
				removeTokenCookies(&w, r)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Panicf("panic: %+v", authErr)
				removeTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			refreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No refresh Cookie")
				removeTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Panicf("panic: %+v", refreshErr)
				removeTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			reqCsrfToken := fetchCsrfFromRequest(r)
			log.Println("Fetched csrfSecret from request : ", reqCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err := jwt.CheckAndRefreshTokens(authCookie.Value, refreshCookie.Value, reqCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attempt! JWT's not valid")
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					log.Panic("error is not nil")
					log.Panicf("panic: %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("Successfully refreshed JWT's")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
			w.WriteHeader(http.StatusOK)
		default:
			// nothing required
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/login":
		log.Println("In login function...!!")
		var login models.Login
		err := json.NewDecoder(r.Body).Decode(&login)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		user, uuid, loginErr := database.LogUserIn(login.Username, login.Password)
		log.Println("Fetched details for a user from DB is :")
		log.Println("User is :", user)
		log.Println("uuid is : ", uuid)
		if loginErr != nil {
			log.Println("Login error is :", loginErr)
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			//authTokenString, refreshTokenString, _, err := jwt.CreateNewTokens(uuid, user.Role)
			//if err != nil {
			//	http.Error(w, http.StatusText(500), 500)
			//}
			//log.Println("Auth token is :", authTokenString)
			//log.Println("Refresh token is :", refreshTokenString)
			//setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("User logged in successfully....\n User's uuid is: %s", uuid)))
		}

	case "/register":
		switch r.Method {
		case "GET":
			w.Write([]byte("Hello From Register Page...!!"))
		case "POST":
			log.Println("In register function....!!")
			var user models.Register
			err := json.NewDecoder(r.Body).Decode(&user)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, _, err = database.FetchUserByUsername(user.Username)
			if err == nil {
				http.Error(w, "User already registered", http.StatusBadRequest)
			} else {
				uuid, err := database.StoreUser(user.Username, user.Password, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("uuid for a user from DB is : ", uuid)
				authTokenString, refreshTokenString, csrfSecret, err := jwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("Auth token is : ", authTokenString)
				log.Println("Refresh Token is :", refreshTokenString)
				fmt.Println("csrfSecret is : ", csrfSecret)
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("User has been registered successfully"))
			}

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		log.Println("Logging out the user...!!")
		uuid, refreshJtiPresent := removeTokenCookies(&w, r)
		if refreshJtiPresent == false {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("user has already been logged out ...!!"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("User logged out successfully....\n User's uuid is: %s", uuid)))
		}
	case "/deleteUser":
		log.Println("Deleting the user...!!")
		authCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			log.Println("unauthorized attempt! no auth cookie")
			_, _ = removeTokenCookies(&w, r)
			return
		} else if authErr != nil {
			log.Panicf("panic : %+v", authErr)
			_, _ = removeTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}
		uuid, uuidErr := jwt.FetchUUID(authCookie.Value)
		if uuidErr != nil {
			log.Panicf("panic : %+v", uuidErr)
			_, _ = removeTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}
		_, _ = removeTokenCookies(&w, r)
		_, err := database.FetchUserById(uuid)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("user has already been deleted  ...!!"))
		} else {
			database.DeleteUser(uuid)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("User deleted successfully....\n User's uuid is: %s", uuid)))
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func removeTokenCookies(w *http.ResponseWriter, r *http.Request) (string, bool) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	RefreshCookie, err := r.Cookie("RefreshToken")
	if err == http.ErrNoCookie {
		return "", true
	} else if err != nil {
		log.Panicf("panic : %+v", err)
		http.Error(*w, http.StatusText(500), 500)
	}
	log.Println("Revoking refresh token...")
	uuid, refreshJtiPresent, err := jwt.RevokeRefreshToken(w, RefreshCookie.Value)
	if err != nil {
		log.Panicf("panic : %+v", err)
		http.Error(*w, http.StatusText(500), 500)
	}
	log.Println("Token Cookies Have been removed successfully....!!")
	return uuid, refreshJtiPresent
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

func fetchCsrfFromRequest(r *http.Request) string {
	return r.Header.Get("X-CSRF-Token")
}
