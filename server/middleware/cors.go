package middleware

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/dewciu/dew_auth_server/server/config"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// CORS returns a middleware that handles CORS
func CORS(cfg config.CORSConfig) gin.HandlerFunc {
	allowOrigins := strings.Join(cfg.AllowOrigins, ",")
	allowMethods := strings.Join(cfg.AllowMethods, ",")
	allowHeaders := strings.Join(cfg.AllowHeaders, ",")
	exposeHeaders := strings.Join(cfg.ExposeHeaders, ",")

	logrus.Debugf("CORS middleware configured with origins: %s", allowOrigins)

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Set CORS headers on all responses
		c.Header("Access-Control-Allow-Origin", getAllowOrigin(origin, cfg.AllowOrigins))
		c.Header("Access-Control-Allow-Methods", allowMethods)
		c.Header("Access-Control-Allow-Headers", allowHeaders)
		c.Header("Access-Control-Expose-Headers", exposeHeaders)
		c.Header("Access-Control-Max-Age", strconv.Itoa(cfg.MaxAge))

		if cfg.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// If this is a preflight OPTIONS request, respond with OK and exit
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

// getAllowOrigin determines if the given origin is allowed
func getAllowOrigin(origin string, allowedOrigins []string) string {
	if len(allowedOrigins) == 0 {
		return ""
	}

	if slices.Contains(allowedOrigins, "*") {
		return origin
	}

	if slices.Contains(allowedOrigins, origin) {
		return origin
	}

	// If not allowed, return the first allowed origin (most secure option)
	return allowedOrigins[0]
}
