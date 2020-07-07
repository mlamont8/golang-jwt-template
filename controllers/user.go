package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/mlamont8/golang-jwt-template/models"
)

type UserController struct{}

func NewUserController() *UserController {
	return &UserController{}
}

// First sample user from storage
var user = models.User{
	ID:       1,
	Username: "username",
	Password: "password",
}

func (uc UserController) Login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var u models.User

	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//compare the user from the request, with the one we defined:
	if user.Username != u.Username || user.Password != u.Password {
		http.Error(w, "Username and/or password do not match", http.StatusForbidden)
		return
	}

	ts, err := CreateToken(user.ID)
	if err != nil {
		http.Error(w, "Error creating tokens", http.StatusBadRequest)
		return
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}
	fmt.Println(tokens, err)
}
