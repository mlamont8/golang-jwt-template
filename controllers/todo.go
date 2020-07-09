package controllers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/mlamont8/golang-jwt-template/models"
)

type TodoController struct{}

func NewTodoController() *TodoController {
	return &TodoController{}
}

func (tc TodoController) CreateTodo(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var td models.Todo

	if r.Body == nil {
		http.Error(w, "Empty Todo", 400)
		return
	}
	err := json.NewDecoder(r.Body).Decode(&td)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	tokenAuth, err := ExtractTokenMetadata(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userId, err := FetchAuth(tokenAuth)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	td.UserID = userId

	// you can proceed to save the Todo to a database
	// but we will just return it to the caller here:
	if r.Body == nil {
		http.Error(w, "Please send a request body", 400)
		return
	}
	err = json.NewEncoder(w).Encode(td)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	log.Println("Todo Created")
}
