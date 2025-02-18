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
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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
}

func NewOAuthServer(config *ServerConfig) OAuthServer {
	return OAuthServer{
		database:     config.Database,
		router:       config.Router,
		tlsPaths:     config.TLSPaths,
		sessionStore: config.SessionStore,
	}
}

type OAuthServer struct {
	database     *gorm.DB
	router       *gin.Engine
	tlsPaths     TLSPaths
	sessionStore sessions.Store
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
	s.setRoutes(controllers, services)
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

	s.router.GET("", controllers.IndexController.IndexHandler)
	s.router.GET(AllEndpoints.Oauth2RegisterUser, controllers.UserRegisterController.RegisterHandler)
	s.router.POST(AllEndpoints.Oauth2RegisterUser, controllers.UserRegisterController.RegisterHandler)
	s.router.GET(AllEndpoints.OAuth2Login, controllers.UserLoginController.LoginHandler)
	s.router.POST(AllEndpoints.OAuth2Login, controllers.UserLoginController.LoginHandler)
	s.router.POST(AllEndpoints.OAuth2Token, controllers.AccessTokenController.Issue)

	sessionGroup := s.router.Group("", middleware.SessionValidate(AllEndpoints.OAuth2Login))

	sessionGroup.GET(AllEndpoints.OAuth2Authorize, controllers.AuthorizationController.Authorize)
	sessionGroup.GET(AllEndpoints.OAuth2RegisterClient, controllers.ClientRegisterController.RegisterHandler)
	sessionGroup.POST(AllEndpoints.OAuth2RegisterClient, controllers.ClientRegisterController.RegisterHandler)
	sessionGroup.GET(AllEndpoints.OAuth2Consent, controllers.ConsentController.ConsentHandler)
	sessionGroup.POST(AllEndpoints.OAuth2Consent, controllers.ConsentController.ConsentHandler)

	clientAuthGroup := s.router.Group("", middleware.AuthorizeClientBasic(services.ClientService))
	clientAuthGroup.POST(AllEndpoints.OAuth2Introspect, controllers.IntrospectionController.Introspect)
	clientAuthGroup.POST(AllEndpoints.OAuth2Revoke, controllers.RevocationController.Revoke)
}
