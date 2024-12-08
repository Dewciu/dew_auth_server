package main

import (
	"context"
	"os"
	"path"

	"github.com/dewciu/dew_auth_server/server"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/services"
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

	repositories := getRepositories(db)
	services := getServices(repositories)
	controllers := getControllers(services)

	oauthServer.Configure(controllers)
	oauthServer.Run(ctx, serveAddress)
}

func getControllers(services *services.Services) *controllers.Controllers {
	accessTokenController := controllers.NewAccessTokenController(
		&services.AccessTokenService,
	)
	return &controllers.Controllers{
		AccessTokenController: accessTokenController,
	}
}

func getServices(repositories *repositories.Repositories) *services.Services {

	accessTokenService := services.NewAccessTokenService(&repositories.AccessTokenRepository)
	return &services.Services{
		AccessTokenService: accessTokenService,
	}
}

func getRepositories(db *gorm.DB) *repositories.Repositories {
	accessTokenRepository := repositories.NewAccessTokenRepository(db)
	return &repositories.Repositories{
		AccessTokenRepository: accessTokenRepository,
	}
}
