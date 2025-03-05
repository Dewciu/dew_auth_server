package middleware

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/dewciu/dew_auth_server/server/config"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/utils"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
	"github.com/sirupsen/logrus"
)

// RateLimiter returns a middleware function that applies rate limiting
func RateLimiter(config *config.RateLimiterConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.Enabled {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		if slices.Contains(config.ExemptedIPs, clientIP) {
			c.Next()
			return
		}

		key, err := GetRateLimiterKey(c, config)
		if err != nil {
			logrus.WithError(err).Warn("Failed to generate rate limit key")
			c.Next()
			return
		}

		count, err := config.Store.Increment(c.Request.Context(), key, config.Window)
		if err != nil {
			logrus.WithError(err).Error("Rate limiter store error")
			c.Next()
			return
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(config.MaxRequests))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(config.MaxRequests-count))

		// If over the limit, return 429 Too Many Requests
		if count > config.MaxRequests {
			e := oautherrors.NewOAuthTooManyRequestsError(
				fmt.Errorf("rate limit exceeded: %d requests in %v window", config.MaxRequests, config.Window),
			)
			c.Header("Retry-After", strconv.Itoa(int(config.Window.Seconds())))
			c.AbortWithStatusJSON(ginerr.NewErrorResponseFrom(
				ginerr.DefaultErrorRegistry,
				c.Request.Context(),
				e,
			))
			return
		}

		c.Next()
	}
}

// GetRateLimiterKey generates a key for rate limiting based on the configuration and request
func GetRateLimiterKey(c *gin.Context, config *config.RateLimiterConfig) (string, error) {
	var key string

	routeKey := ""
	rateLimitPrefix := "ratelimit"

	if config.IncludeRoute {
		routeKey = ":" + c.FullPath()
	}

	switch config.LimiterType {
	case constants.RateLimitingIpBased:
		clientIP := c.ClientIP()
		key = fmt.Sprintf("%s:ip:%s%s", rateLimitPrefix, clientIP, routeKey)
	case constants.RateLimitingClientBased:
		var clientID string
		if c.Request.Method == "POST" {
			clientID = c.PostForm("client_id")
		}
		if clientID == "" {
			clientID = c.Query("client_id")
		}
		if clientID == "" {
			// Try to extract from Authorization header
			auth := c.GetHeader("Authorization")
			if auth != "" {
				c, _, err := utils.GetCredentialsFromBasicAuthHeader(auth)

				if err != nil {
					return "", fmt.Errorf("failed to extract client ID from Authorization header: %v", err)
				}

				clientID = c
			}
		}

		if clientID == "" {
			return "", fmt.Errorf("client ID not found for rate limiting")
		}
		key = fmt.Sprintf("%s:client:%s%s", rateLimitPrefix, clientID, routeKey)
	case constants.RateLimitingUserBased:
		userID, exists := c.Get("user_id")
		if !exists {
			return "", fmt.Errorf("user ID not found for rate limiting")
		}
		key = fmt.Sprintf("%s:user:%s%s", rateLimitPrefix, userID, routeKey)
	case constants.RateLimitingTokenBased:
		clientIP := c.ClientIP()
		clientID := c.PostForm("client_id")
		if clientID != "" {
			key = fmt.Sprintf("%s:token:%s:%s%s", rateLimitPrefix, clientIP, clientID, routeKey)
		} else {
			key = fmt.Sprintf("%s:token:%s%s", rateLimitPrefix, clientIP, routeKey)
		}
	case constants.RateLimitingGlobalBased:
		key = fmt.Sprintf("%s:global%s", rateLimitPrefix, routeKey)
	default:
		return "", fmt.Errorf("unknown rate limiter type: %s", config.LimiterType)
	}

	return key, nil
}
