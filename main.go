package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-redis/redis/v8"
	"github.com/julienschmidt/httprouter"
	"github.com/mlamont8/golang-jwt-template/controllers"
)

var client *redis.Client
var ctx = context.Background()

func init() {
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr:     dsn, //redis port
		Password: "",
		DB:       0,
	})
	_, err := client.Ping(ctx).Result()
	if err != nil {
		log.Println("Error connecting to redis", err)
		return
	}

	log.Println("Successfully connected to Redis")

}

func main() {
	router := httprouter.New()
	uc := controllers.NewUserController()
	tc := controllers.NewTodoController()
	router.POST("/login", uc.Login)
	router.POST("/logout", uc.Logout)
	router.POST("/todo", tc.CreateTodo)

	http.ListenAndServe("localhost:8080", router)
}
