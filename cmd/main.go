package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/dewciu/dew_auth_server/server"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	serveAddressEnvVar            = "HTTP_SERVE_ADDRESS"
	dbConnectionURLEnvVar         = "DATABASE_CONNECTION_URL"
	templatePathEnvVar            = "TEMPLATE_PATH"
	redisAddressEnvVar            = "REDIS_ADDRESS"
	redisMaxIdleConnectionsEnvVar = "REDIS_MAX_IDLE_CONNECTIONS"
	sessionLifetimeEnvVar         = "SESSION_LIFETIME"
	sessionSigningKeyEnvVar       = "SESSION_SIGNING_KEY"
	sessionEncriptionKeyEnvVar    = "SESSION_ENCRIPTION_KEY"
)

func main() {
	_ = godotenv.Load(
		path.Join("cmd", ".env"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		serveAddress            = os.Getenv(serveAddressEnvVar)
		dbConnectionURL         = os.Getenv(dbConnectionURLEnvVar)
		templatePath            = os.Getenv(templatePathEnvVar)
		redisAddress            = os.Getenv(redisAddressEnvVar)
		redisMaxIdleConnections = os.Getenv(redisMaxIdleConnectionsEnvVar)
		sessionLifetime         = os.Getenv(sessionLifetimeEnvVar)
		sessionSigningKey       = os.Getenv(sessionSigningKeyEnvVar)
		sessionEncriptionKey    = os.Getenv(sessionEncriptionKeyEnvVar)
	)

	router := gin.New()

	db, err := gorm.Open(postgres.Open(dbConnectionURL))
	if err != nil {
		logrus.WithError(err).Fatalf("failed to connect to database: %v", err)
	}

	maxIdleConnections, err := strconv.Atoi(redisMaxIdleConnections)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to convert redisMaxIdleConnections to int: %v", err)
	}

	sessLifetime, err := strconv.Atoi(sessionLifetime)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to convert sessionLifetime to int: %v", err)
	}

	signKey, err := hex.DecodeString(sessionSigningKey)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to decode sessionSigning %s to bytes: %v", sessionSigningKey, err)
	}

	encKey, err := hex.DecodeString(sessionEncriptionKey)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to decode sessionEncription %s to bytes: %v", sessionEncriptionKey, err)
	}

	sessionStore, err := redis.NewStore(
		maxIdleConnections,
		"tcp",
		redisAddress,
		"",
		signKey,
		encKey,
	)

	if err != nil {
		logrus.WithError(err).Fatalf("failed to create redis session store: %v", err)
	}

	sessionStore.Options(
		sessions.Options{
			Path:     "/", // cookie path
			MaxAge:   sessLifetime,
			HttpOnly: true,
			Secure:   false, // set to true if using https
			SameSite: http.SameSiteLaxMode,
		},
	)

	serverConfig := server.ServerConfig{
		Database:     db,
		Router:       router,
		SessionStore: sessionStore,
	}

	oauthServer := server.NewOAuthServer(&serverConfig)

	repositories := getRepositories(db)
	services := getServices(repositories)
	controllers := getControllers(templatePath, services)

	oauthServer.Configure(controllers)
	oauthServer.Run(ctx, serveAddress)
}

func getControllers(templatePath string, services *services.Services) *controllers.Controllers {
	accessTokenController := controllers.NewAccessTokenController(
		services.AuthorizationCodeGrantService,
	)
	clientRegisterController := controllers.NewRegisterController(
		templatePath,
		services.ClientService,
	)
	userRegisterController := controllers.NewUserRegisterController(
		templatePath,
		services.UserService,
	)
	authorizationController := controllers.NewAuthorizationController(
		services.AuthorizationService,
		services.ConsentService,
		server.AllEndpoints.OAuth2Consent,
	)
	userLoginController := controllers.NewUserLoginController(
		templatePath,
		services.UserService,
		services.ConsentService,
	)
	indexController := controllers.NewIndexController(templatePath)
	consentController := controllers.NewConsentController(
		templatePath,
		services.ClientService,
		services.ConsentService,
	)
	return &controllers.Controllers{
		AccessTokenController:    accessTokenController,
		ClientRegisterController: clientRegisterController,
		AuthorizationController:  authorizationController,
		UserRegisterController:   userRegisterController,
		UserLoginController:      userLoginController,
		IndexController:          indexController,
		ConsentController:        consentController,
	}
}

func getServices(repositories *repositories.Repositories) *services.Services {

	accessTokenService := services.NewAccessTokenService(repositories.AccessTokenRepository)
	clientService := services.NewClientService(repositories.ClientRepository)
	authorizationCodeService := services.NewAuthorizationCodeService(repositories.AuthorizationCodeRepository)
	refreshTokenService := services.NewRefreshTokenService(repositories.RefreshTokenRepository)
	userService := services.NewUserService(repositories.UserRepository)
	authorizationCodeGrantService := services.NewAuthorizationCodeGrantService(
		accessTokenService,
		clientService,
		authorizationCodeService,
		refreshTokenService,
	)
	authorizationService := services.NewAuthorizationService(
		clientService,
		authorizationCodeService,
		userService,
	)

	consentService := services.NewConsentService(repositories.ConsentRepository)

	return &services.Services{
		AccessTokenService:            accessTokenService,
		ClientService:                 clientService,
		AuthorizationCodeService:      authorizationCodeService,
		RefreshTokenService:           refreshTokenService,
		UserService:                   userService,
		AuthorizationCodeGrantService: authorizationCodeGrantService,
		AuthorizationService:          authorizationService,
		ConsentService:                consentService,
	}
}

func getRepositories(db *gorm.DB) *repositories.Repositories {
	accessTokenRepository := repositories.NewAccessTokenRepository(db)
	clientRepository := repositories.NewClientRepository(db)
	authorizationCodeRepository := repositories.NewAuthorizationCodeRepository(db)
	refreshTokenRepository := repositories.NewRefreshTokenRepository(db)
	userRepository := repositories.NewUserRepository(db)
	consentRepository := repositories.NewConsentRepository(db)

	return &repositories.Repositories{
		AccessTokenRepository:       accessTokenRepository,
		ClientRepository:            clientRepository,
		AuthorizationCodeRepository: authorizationCodeRepository,
		RefreshTokenRepository:      refreshTokenRepository,
		UserRepository:              userRepository,
		ConsentRepository:           consentRepository,
	}
}
