package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/mlamont8/golang-jwt-template/controllers"
)

func main() {
	router := httprouter.New()
	uc := controllers.NewUserController()
	router.POST("/login", uc.Login)
	http.ListenAndServe("localhost:8080", router)
}
