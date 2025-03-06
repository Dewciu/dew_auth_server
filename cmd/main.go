package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"strconv"

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

const (
	serveAddressEnvVar            = "HTTP_SERVE_ADDRESS"
	dbConnectionURLEnvVar         = "DATABASE_CONNECTION_URL"
	templatePathEnvVar            = "TEMPLATE_PATH"
	redisAddressEnvVar            = "REDIS_ADDRESS"
	redisMaxIdleConnectionsEnvVar = "REDIS_MAX_IDLE_CONNECTIONS"
	sessionLifetimeEnvVar         = "SESSION_LIFETIME"
	sessionSigningKeyEnvVar       = "SESSION_SIGNING_KEY"
	sessionEncriptionKeyEnvVar    = "SESSION_ENCRIPTION_KEY"
	certPathEnvVar                = "TLS_CERT_PATH"
	keyPathEnvVar                 = "TLS_KEY_PATH"
	rateLimitingEnabledEnvVar     = "RATE_LIMITING_ENABLED"
	rateLimitTokenLimitEnvVar     = "RATE_LIMIT_TOKEN"
	rateLimitAuthLimitEnvVar      = "RATE_LIMIT_AUTH"
	rateLimitLoginLimitEnvVar     = "RATE_LIMIT_LOGIN"
	rateLimitCommonLimitEnvVar    = "RATE_LIMIT_COMMON"
	rateLimitWindowSecsEnvVar     = "RATE_LIMIT_WINDOW_SECS"
	rateLimitExemptedIPsEnvVar    = "RATE_LIMIT_EXEMPTED_IPS"
	corsAllowOriginsEnvVar        = "CORS_ALLOW_ORIGINS"
	corsAllowMethodsEnvVar        = "CORS_ALLOW_METHODS"
	corsAllowHeadersEnvVar        = "CORS_ALLOW_HEADERS"
	corsExposeHeadersEnvVar       = "CORS_EXPOSE_HEADERS"
	corsAllowCredentialsEnvVar    = "CORS_ALLOW_CREDENTIALS"
	corsMaxAgeEnvVar              = "CORS_MAX_AGE"
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
		certPath                = os.Getenv(certPathEnvVar)
		keyPath                 = os.Getenv(keyPathEnvVar)
		rateLimitingEnabled     = os.Getenv(rateLimitingEnabledEnvVar)
		rateLimitToken          = os.Getenv(rateLimitTokenLimitEnvVar)
		rateLimitAuth           = os.Getenv(rateLimitAuthLimitEnvVar)
		rateLimitLogin          = os.Getenv(rateLimitLoginLimitEnvVar)
		rateLimitCommon         = os.Getenv(rateLimitCommonLimitEnvVar)
		rateLimitWindowSecs     = os.Getenv(rateLimitWindowSecsEnvVar)
		rateLimitExemptedIPs    = os.Getenv(rateLimitExemptedIPsEnvVar)
		corsAllowOrigins        = os.Getenv(corsAllowOriginsEnvVar)
		corsAllowMethods        = os.Getenv(corsAllowMethodsEnvVar)
		corsAllowHeaders        = os.Getenv(corsAllowHeadersEnvVar)
		corsExposeHeaders       = os.Getenv(corsExposeHeadersEnvVar)
		corsAllowCredentials    = os.Getenv(corsAllowCredentialsEnvVar)
		corsMaxAge              = os.Getenv(corsMaxAgeEnvVar)
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

	redisClient := redis.NewClient(
		&redis.Options{
			Addr: redisAddress,
		},
	)
	defer redisClient.Close()

	sessionStore, err := redisSessions.NewStore(
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
			Secure:   true, // set to true when using HTTPS
			SameSite: http.SameSiteLaxMode,
		},
	)

	rateConfig := config.ParseRateLimitConfig(
		rateLimitingEnabled,
		rateLimitToken,
		rateLimitAuth,
		rateLimitLogin,
		rateLimitCommon,
		rateLimitWindowSecs,
		rateLimitExemptedIPs,
	)

	corsConfig := config.ParseCORSConfig(
		corsAllowOrigins,
		corsAllowMethods,
		corsAllowHeaders,
		corsExposeHeaders,
		corsAllowCredentials,
		corsMaxAge,
	)

	serverConfig := server.ServerConfig{
		Database: db,
		Router:   router,
		TLSPaths: server.TLSPaths{
			Cert: certPath,
			Key:  keyPath,
		},
		SessionStore: sessionStore,
		RedisClient:  redisClient,
		RateLimiting: rateConfig,
		CORSConfig:   corsConfig,
	}

	oauthServer := server.NewOAuthServer(&serverConfig)

	repositories := getRepositories(db)
	cacheRepositories := getCacheRepositories(redisClient)
	services := getServices(repositories, cacheRepositories)
	controllers := getControllers(templatePath, services)

	oauthServer.Configure(controllers, services)
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

func getCacheRepositories(rdClient *redis.Client) *cacherepositories.CacheRepositories {
	authCodeLifetime := os.Getenv("AUTH_CODE_LIFETIME")
	accessTokenLifetime := os.Getenv("ACCESS_TOKEN_LIFETIME")
	refreshTokenLifetime := os.Getenv("REFRESH_TOKEN_LIFETIME")

	//TODO: Consider doing some external configuration
	authCodeLifetimeInt, err := strconv.Atoi(authCodeLifetime)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to convert authCodeLifetime to int: %v", err)
	}

	accessTokenLifetimeInt, err := strconv.Atoi(accessTokenLifetime)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to convert accessTokenLifetime to int: %v", err)
	}

	refreshTokenLifetimeInt, err := strconv.Atoi(refreshTokenLifetime)
	if err != nil {
		logrus.WithError(err).Fatalf("failed to convert refreshTokenLifetime to int: %v", err)
	}

	authorizationCodeRepository := cacherepositories.NewAuthorizationCodeRepository(
		rdClient,
		authCodeLifetimeInt,
	)

	accessTokenRepository := cacherepositories.NewAccessTokenRepository(
		rdClient,
		accessTokenLifetimeInt,
	)

	refreshTokenRepository := cacherepositories.NewRefreshTokenRepository(
		rdClient,
		refreshTokenLifetimeInt,
	)

	return &cacherepositories.CacheRepositories{
		AuthorizationCodeRepository: authorizationCodeRepository,
		AccessTokenRepository:       accessTokenRepository,
		RefreshTokenRepository:      refreshTokenRepository,
	}
}
