package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/dewciu/dew_auth_server/server/config"
	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/middleware"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

type TLSPaths struct {
	Cert string
	Key  string
}

type ServerConfig struct {
	Database     *gorm.DB
	Router       *gin.Engine
	TLSPaths     TLSPaths
	SessionStore sessions.Store
	RedisClient  *redis.Client
	RateLimiting config.ServerRateLimitingConfig
}

type OAuthServer struct {
	database            *gorm.DB
	router              *gin.Engine
	tlsPaths            TLSPaths
	sessionStore        sessions.Store
	redisClient         *redis.Client
	rateLimitingEnabled bool
	rateLimiters        map[string]*config.RateLimiterConfig
}

func NewOAuthServer(cfg *ServerConfig) OAuthServer {
	return OAuthServer{
		database:            cfg.Database,
		router:              cfg.Router,
		tlsPaths:            cfg.TLSPaths,
		sessionStore:        cfg.SessionStore,
		redisClient:         cfg.RedisClient,
		rateLimitingEnabled: cfg.RateLimiting.Enabled,
		rateLimiters:        config.GetRateLimiters(cfg.RateLimiting, cfg.RedisClient),
	}
}

func (s *OAuthServer) Configure(
	controllers *controllers.Controllers,
	services *services.Services,
) {
	err := s.migrate()
	if err != nil {
		logrus.WithError(err).Fatalf("failed to migrate database: %v", err)
	}

	s.setMiddleware()
	s.setErrorHandlers()
	s.setRoutes(controllers, services)
}

func (s *OAuthServer) Run(ctx context.Context, serveAddress string) {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	srv := &http.Server{
		Addr:    serveAddress,
		Handler: s.router,

		// To prevent G112 (CWE-400), for protection against Slowloris Attacks
		ReadTimeout: 10 * time.Second,
	}

	shutdownTimeout := 10 * time.Second

	// Initializing the server in a goroutine so that it won't block the graceful shutdown
	go func() {
		logrus.Infof("Starting HTTP server on %s", serveAddress)
		if err := srv.ListenAndServeTLS(s.tlsPaths.Cert, s.tlsPaths.Key); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("failed to start HTTP server")
		}
	}()

	// Await for the context to be done (shutdown signal)
	<-ctx.Done()

	stop()
	logrus.Info("Interrupt signal received, shutting down the server")

	timeoutContext, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(timeoutContext); err != nil {
		logrus.WithError(err).Error("failed to gracefully shutdown the server")
	}

	logrus.Info("Server shutdown complete")
}

func (s *OAuthServer) migrate() error {
	err := s.database.AutoMigrate(
		&models.User{},
		&models.Client{},
		&models.Consent{},
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *OAuthServer) setMiddleware() {
	s.router.Static("/oauth2/styles", "server/controllers/templates/styles")
	s.router.Use(gin.LoggerWithWriter(logrus.StandardLogger().Out))
	s.router.Use(sessions.Sessions("session", s.sessionStore))

}

func (s *OAuthServer) setErrorHandlers() {
	ginerr.RegisterErrorHandler(oautherrors.OAuthInternalServerErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInputValidationErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthUnsupportedGrantTypeErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthUnsupportedTokenTypeErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInvalidClientErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInvalidGrantErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthAccessDeniedErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInvalidScopeErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthInvalidTokenErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthUnauthorizedClientErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthUnsupportedResponseTypeErrorHandler)
	ginerr.RegisterErrorHandler(oautherrors.OAuthTooManyRequestsErrorHandler)
}

func (s *OAuthServer) setRoutes(
	controllers *controllers.Controllers,
	services *services.Services,
) {
	s.router.GET("../openapi.yaml", func(c *gin.Context) {
		c.File("./openapi.yaml")
	})

	s.router.GET("/swagger/*any", ginSwagger.CustomWrapHandler(&ginSwagger.Config{
		URL: "/openapi.yaml", // Point to your OpenAPI specification
	}, swaggerFiles.Handler))

	commonGroup := s.getCommonGroup()
	commonGroup.GET("", controllers.IndexController.IndexHandler)

	userGroup := s.getUserGroup()
	userGroup.GET(AllEndpoints.Oauth2RegisterUser, controllers.UserRegisterController.RegisterHandler)
	userGroup.POST(AllEndpoints.Oauth2RegisterUser, controllers.UserRegisterController.RegisterHandler)
	userGroup.GET(AllEndpoints.OAuth2Login, controllers.UserLoginController.LoginHandler)
	userGroup.POST(AllEndpoints.OAuth2Login, controllers.UserLoginController.LoginHandler)

	authGroup := s.getAuthGroup()
	authGroup.GET(AllEndpoints.OAuth2Authorize, controllers.AuthorizationController.Authorize)
	authGroup.GET(AllEndpoints.OAuth2RegisterClient, controllers.ClientRegisterController.RegisterHandler)
	authGroup.POST(AllEndpoints.OAuth2RegisterClient, controllers.ClientRegisterController.RegisterHandler)
	authGroup.GET(AllEndpoints.OAuth2Consent, controllers.ConsentController.ConsentHandler)
	authGroup.POST(AllEndpoints.OAuth2Consent, controllers.ConsentController.ConsentHandler)

	tokenGroup := s.getTokenGroup(services)
	tokenGroup.POST(AllEndpoints.OAuth2Introspect, controllers.IntrospectionController.Introspect)
	tokenGroup.POST(AllEndpoints.OAuth2Revoke, controllers.RevocationController.Revoke)
	tokenGroup.POST(AllEndpoints.OAuth2Token, controllers.AccessTokenController.Issue)
}

func (s *OAuthServer) getUserGroup() *gin.RouterGroup {
	handlers := []gin.HandlerFunc{}

	if s.rateLimitingEnabled {
		handlers = append(handlers, middleware.RateLimiter(s.rateLimiters["user"]))
	}

	loginGroup := s.router.Group("", handlers...)

	return loginGroup
}

func (s *OAuthServer) getAuthGroup() *gin.RouterGroup {
	handlers := []gin.HandlerFunc{}

	if s.rateLimitingEnabled {
		handlers = append(handlers, middleware.RateLimiter(s.rateLimiters["auth"]))
	}

	handlers = append(handlers, middleware.SessionValidate(AllEndpoints.OAuth2Login))

	authGroup := s.router.Group("", handlers...)

	return authGroup
}

func (s *OAuthServer) getTokenGroup(
	services *services.Services,
) *gin.RouterGroup {
	handlers := []gin.HandlerFunc{}

	if s.rateLimitingEnabled {
		handlers = append(handlers, middleware.RateLimiter(s.rateLimiters["token"]))
	}

	handlers = append(handlers, middleware.AuthorizeClient(services.ClientService))

	tokenGroup := s.router.Group("", handlers...)

	return tokenGroup
}

func (s *OAuthServer) getCommonGroup() *gin.RouterGroup {
	handlers := []gin.HandlerFunc{}

	if s.rateLimitingEnabled {
		handlers = append(handlers, middleware.RateLimiter(s.rateLimiters["common"]))
	}

	tokenGroup := s.router.Group("", handlers...)

	return tokenGroup
}
