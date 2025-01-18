package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/dewciu/dew_auth_server/server/controllers"
	"github.com/dewciu/dew_auth_server/server/models"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

type ServerConfig struct {
	Database *gorm.DB
	Router   *gin.Engine
}

func NewOAuthServer(config *ServerConfig) OAuthServer {
	return OAuthServer{
		database: config.Database,
		router:   config.Router,
	}
}

type OAuthServer struct {
	database *gorm.DB
	router   *gin.Engine
}

func (s *OAuthServer) Configure(controllers *controllers.Controllers) {
	err := s.migrate()
	if err != nil {
		logrus.WithError(err).Fatalf("failed to migrate database: %v", err)
	}

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
		&models.Session{},
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *OAuthServer) setRoutes(controllers *controllers.Controllers) {
	s.router.GET("../openapi.yaml", func(c *gin.Context) {
		c.File("./openapi.yaml")
	})

	s.router.GET("/swagger/*any", ginSwagger.CustomWrapHandler(&ginSwagger.Config{
		URL: "/openapi.yaml", // Point to your OpenAPI specification
	}, swaggerFiles.Handler))

	s.router.POST("/oauth/token", controllers.AccessTokenController.Issue)
	s.router.GET("/oauth/authorize", controllers.AuthorizationController.Authorize)
	s.router.GET("/register-client", controllers.ClientRegisterController.RegisterHandler)
	s.router.POST("/register-client", controllers.ClientRegisterController.RegisterHandler)
	s.router.GET("/register-user", controllers.UserRegisterController.RegisterHandler)
	s.router.POST("/register-user", controllers.UserRegisterController.RegisterHandler)
	s.router.GET("/login", controllers.UserLoginController.LoginHandler)
	s.router.POST("/login", controllers.UserLoginController.LoginHandler)
	s.router.GET("", controllers.IndexController.IndexHandler)
}
