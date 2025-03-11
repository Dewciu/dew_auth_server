package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"path"

	"github.com/dewciu/dew_auth_server/server"
	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/config"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/repositories"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-contrib/sessions"
	redisSessions "github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	var configPath string

	flag.StringVar(&configPath, "config", "", "path to the configuration file")
	flag.Parse()

	_ = godotenv.Load(
		path.Join("cmd", ".env"),
	)

	cfg, err := config.LoadConfig(configPath)

	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config.ConfigureLogging(cfg.Logging)

	router := gin.New()

	db, err := gorm.Open(postgres.Open(cfg.Database.URL))
	if err != nil {
		logrus.WithError(err).Fatalf("failed to connect to database: %v", err)
	}

	redisClient := redis.NewClient(
		&redis.Options{
			Addr: cfg.Redis.Address,
		},
	)
	defer redisClient.Close()

	signKey, err := hex.DecodeString(cfg.Session.SigningKey)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to decode sessionSigning %s to bytes: %v", cfg.Session.SigningKey, err)
	}

	encKey, err := hex.DecodeString(cfg.Session.EncryptionKey)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to decode sessionEncription %s to bytes: %v", cfg.Session.EncryptionKey, err)
	}

	sessionStore, err := redisSessions.NewStore(
		cfg.Redis.MaxIdleConnections,
		"tcp",
		cfg.Redis.Address,
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
			MaxAge:   int(cfg.Session.Lifetime),
			HttpOnly: true,
			Secure:   true, // set to true when using HTTPS
			SameSite: http.SameSiteLaxMode,
		},
	)

	serverConfig := server.ServerConfig{
		Database: db,
		Router:   router,
		TLSPaths: server.TLSPaths{
			Cert: cfg.Server.TLSCertPath,
			Key:  cfg.Server.TLSKeyPath,
		},
		SessionStore: sessionStore,
		RedisClient:  redisClient,
		RateLimiting: cfg.RateLimit,
		CORSConfig:   cfg.CORS,
	}

	oauthServer := server.NewOAuthServer(&serverConfig)

	repositories := getRepositories(db)
	cacheRepositories := getCacheRepositories(cfg, redisClient)
	services := getServices(repositories, cacheRepositories)
	controllers := getControllers(cfg.Server.TemplatePath, services)

	oauthServer.Configure(controllers, services)
	oauthServer.Run(
		ctx,
		fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
	)
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
		services.ClientService,
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
		server.AllEndpoints.OAuth2Authorize,
	)
	introspectionController := controllers.NewIntrospectionController(
		services.AccessTokenService,
		services.RefreshTokenService,
	)
	revocationController := controllers.NewRevocationController(
		services.AccessTokenService,
		services.RefreshTokenService,
	)
	return &controllers.Controllers{
		AccessTokenController:    accessTokenController,
		ClientRegisterController: clientRegisterController,
		AuthorizationController:  authorizationController,
		UserRegisterController:   userRegisterController,
		UserLoginController:      userLoginController,
		IndexController:          indexController,
		ConsentController:        consentController,
		IntrospectionController:  introspectionController,
		RevocationController:     revocationController,
	}
}

func getServices(repositories *repositories.Repositories, cacheRepositories *cacherepositories.CacheRepositories) *services.Services {

	accessTokenService := services.NewAccessTokenService(cacheRepositories.AccessTokenRepository)
	clientService := services.NewClientService(repositories.ClientRepository)
	authorizationCodeService := services.NewAuthorizationCodeService(cacheRepositories.AuthorizationCodeRepository)
	refreshTokenService := services.NewRefreshTokenService(cacheRepositories.RefreshTokenRepository)
	userService := services.NewUserService(repositories.UserRepository)
	authorizationCodeGrantService := services.NewGrantService(
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
	clientRepository := repositories.NewClientRepository(db)
	userRepository := repositories.NewUserRepository(db)
	consentRepository := repositories.NewConsentRepository(db)

	return &repositories.Repositories{
		ClientRepository:  clientRepository,
		UserRepository:    userRepository,
		ConsentRepository: consentRepository,
	}
}

func getCacheRepositories(cfg *config.Config, rdClient *redis.Client) *cacherepositories.CacheRepositories {
	authorizationCodeRepository := cacherepositories.NewAuthorizationCodeRepository(
		rdClient,
		int(cfg.OAuth.AuthCodeLifetime),
	)

	accessTokenRepository := cacherepositories.NewAccessTokenRepository(
		rdClient,
		int(cfg.OAuth.AccessTokenLifetime),
	)

	refreshTokenRepository := cacherepositories.NewRefreshTokenRepository(
		rdClient,
		int(cfg.OAuth.RefreshTokenLifetime),
	)

	return &cacherepositories.CacheRepositories{
		AuthorizationCodeRepository: authorizationCodeRepository,
		AccessTokenRepository:       accessTokenRepository,
		RefreshTokenRepository:      refreshTokenRepository,
	}
}
