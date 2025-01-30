package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/middleware"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

type ServerConfig struct {
	Database     *gorm.DB
	Router       *gin.Engine
	SessionStore sessions.Store
}

func NewOAuthServer(config *ServerConfig) OAuthServer {
	return OAuthServer{
		database:     config.Database,
		router:       config.Router,
		sessionStore: config.SessionStore,
	}
}

type OAuthServer struct {
	database     *gorm.DB
	router       *gin.Engine
	sessionStore sessions.Store
}

func (s *OAuthServer) Configure(controllers *controllers.Controllers) {
	err := s.migrate()
	if err != nil {
		logrus.WithError(err).Fatalf("failed to migrate database: %v", err)
	}

	s.setMiddleware()
	s.setRoutes(controllers)
}

func (s *OAuthServer) Run(ctx context.Context, serveAddress string) {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	//TODO: Make it HTTPS
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
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
		&models.AuthorizationCode{},
		&models.AccessToken{},
		&models.RefreshToken{},
		&models.Consent{},
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *OAuthServer) setMiddleware() {
	s.router.Use(gin.LoggerWithWriter(logrus.StandardLogger().Out))
	s.router.Use(sessions.Sessions("session", s.sessionStore))
}

func (s *OAuthServer) setRoutes(controllers *controllers.Controllers) {
	s.router.GET("../openapi.yaml", func(c *gin.Context) {
		c.File("./openapi.yaml")
	})

	s.router.GET("/swagger/*any", ginSwagger.CustomWrapHandler(&ginSwagger.Config{
		URL: "/openapi.yaml", // Point to your OpenAPI specification
	}, swaggerFiles.Handler))

	s.router.GET("", controllers.IndexController.IndexHandler)
	s.router.GET(endpoints.RegisterUser, controllers.UserRegisterController.RegisterHandler)
	s.router.POST(endpoints.RegisterUser, controllers.UserRegisterController.RegisterHandler)
	s.router.GET(endpoints.OAuth2Login, controllers.UserLoginController.LoginHandler)
	s.router.POST(endpoints.OAuth2Login, controllers.UserLoginController.LoginHandler)
	s.router.POST(endpoints.OAuth2Token, controllers.AccessTokenController.Issue)

	authedGroup := s.router.Group("", middleware.SessionValidate(endpoints.OAuth2Login))
	authedGroup.GET(endpoints.OAuth2Authorize, controllers.AuthorizationController.Authorize)
	authedGroup.GET(endpoints.RegisterClient, controllers.ClientRegisterController.RegisterHandler)
	authedGroup.POST(endpoints.RegisterClient, controllers.ClientRegisterController.RegisterHandler)
	authedGroup.GET(endpoints.OAuth2Consent, controllers.ConsentController.ConsentHandler)
	authedGroup.POST(endpoints.OAuth2Consent, controllers.ConsentController.ConsentHandler)
}
