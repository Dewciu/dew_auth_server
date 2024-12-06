package main

import (
	"context"
	"os"
	"path"

	"github.com/dewciu/dew_auth_server/server"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	serveAddressEnvVar    = "HTTP_SERVE_ADDRESS"
	dbConnectionURLEnvVar = "DATABASE_CONNECTION_URL"
)

func main() {
	_ = godotenv.Load(
		path.Join("cmd", ".env"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		serveAddress    = os.Getenv(serveAddressEnvVar)
		dbConnectionURL = os.Getenv(dbConnectionURLEnvVar)
	)

	router := gin.New()

	db, err := gorm.Open(postgres.Open(dbConnectionURL))
	if err != nil {
		logrus.WithError(err).Fatalf("failed to connect to database: %v", err)
	}

	serverConfig := server.ServerConfig{
		Database: db,
		Router:   router,
	}

	oauthServer := server.NewOAuthServer(&serverConfig)
	oauthServer.Configure()
	oauthServer.Run(ctx, serveAddress)
}
