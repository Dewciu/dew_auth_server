package main

import (
	"context"
	"os"
	"path"

	"github.com/dewciu/dew_auth_server/server"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/handlers"
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
	handlers := getHandlers(services)
	controllers := getControllers(handlers)

	oauthServer.Configure(controllers)
	oauthServer.Run(ctx, serveAddress)
}

func getControllers(handlers *handlers.Handlers) *controllers.Controllers {
	accessTokenController := controllers.NewAccessTokenController(
		handlers.AuthorizationCodeGrantHandler,
	)
	return &controllers.Controllers{
		AccessTokenController: accessTokenController,
	}
}

func getHandlers(services *services.Services) *handlers.Handlers {
	return &handlers.Handlers{
		AuthorizationCodeGrantHandler: handlers.NewAuthorizationCodeGrantHandler(
			services.AccessTokenService,
			services.ClientService,
			services.AuthorizationCodeService,
			services.RefreshTokenService,
		),
	}
}

func getServices(repositories *repositories.Repositories) *services.Services {

	accessTokenService := services.NewAccessTokenService(repositories.AccessTokenRepository)
	clientService := services.NewClientService(repositories.ClientRepository)
	authorizationCodeService := services.NewAuthorizationCodeService(repositories.AuthorizationCodeRepository)
	refreshTokenService := services.NewRefreshTokenService(repositories.RefreshTokenRepository)

	return &services.Services{
		AccessTokenService:       &accessTokenService,
		ClientService:            &clientService,
		AuthorizationCodeService: &authorizationCodeService,
		RefreshTokenService:      &refreshTokenService,
	}
}

func getRepositories(db *gorm.DB) *repositories.Repositories {
	accessTokenRepository := repositories.NewAccessTokenRepository(db)
	clientRepository := repositories.NewClientRepository(db)
	authorizationCodeRepository := repositories.NewAuthorizationCodeRepository(db)
	refreshTokenRepository := repositories.NewRefreshTokenRepository(db)

	return &repositories.Repositories{
		AccessTokenRepository:       accessTokenRepository,
		ClientRepository:            clientRepository,
		AuthorizationCodeRepository: authorizationCodeRepository,
		RefreshTokenRepository:      refreshTokenRepository,
	}
}
