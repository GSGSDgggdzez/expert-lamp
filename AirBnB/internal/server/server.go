package server

import (
	"github.com/gofiber/fiber/v2"
  
	"AirBnB/internal/database"
  
)

type FiberServer struct {
	*fiber.App
  
	db database.Service
  
}

func New() *FiberServer {
	server := &FiberServer{
		App: fiber.New(fiber.Config{
		ServerHeader:            "AirBnB",
		AppName:                 "AirBnB",
	}),
  
		db:  database.New(),
  
	}

	return server
}
