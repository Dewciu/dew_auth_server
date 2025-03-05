package config

import (
	"time"

	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/redis/go-redis/v9"
)

type RateLimiterConfig struct {
	Enabled      bool                           // Whether rate limiting is enabled
	Store        cacherepositories.LimiterStore // Storage mechanism for rate counters
	MaxRequests  int                            // Maximum number of requests allowed in the window
	Window       time.Duration                  // Time window for rate limiting
	LimiterType  string                         // Type of rate limiting to apply (ip, client, user, token)
	ExemptedIPs  []string                       // List of IPs exempt from rate limiting
	IncludeRoute bool                           // Whether to include the route in the rate limit key
}

type ServerRateLimitingConfig struct {
	Enabled      bool
	CommonLimit  int
	TokenLimit   int
	AuthLimit    int
	LoginLimit   int
	ExemptedIPs  []string
	WindowInSecs int
}

func GetRateLimiters(
	config ServerRateLimitingConfig,
	redisClient *redis.Client,
) map[string]*RateLimiterConfig {
	window := time.Duration(config.WindowInSecs) * time.Second

	tokenLimiter := &RateLimiterConfig{
		Enabled:      config.Enabled,
		Store:        cacherepositories.NewRedisStore(redisClient, "token"),
		MaxRequests:  config.TokenLimit,
		Window:       window,
		LimiterType:  constants.RateLimitingTokenBased,
		ExemptedIPs:  config.ExemptedIPs,
		IncludeRoute: true,
	}

	authLimiter := &RateLimiterConfig{
		Enabled:      config.Enabled,
		Store:        cacherepositories.NewRedisStore(redisClient, "auth"),
		MaxRequests:  config.AuthLimit,
		Window:       window,
		LimiterType:  constants.RateLimitingIpBased,
		ExemptedIPs:  config.ExemptedIPs,
		IncludeRoute: true,
	}

	userLimiter := &RateLimiterConfig{
		Enabled:      config.Enabled,
		Store:        cacherepositories.NewRedisStore(redisClient, "user"),
		MaxRequests:  config.LoginLimit,
		Window:       window,
		LimiterType:  constants.RateLimitingIpBased,
		ExemptedIPs:  config.ExemptedIPs,
		IncludeRoute: true,
	}

	commonLimiter := &RateLimiterConfig{
		Enabled:      config.Enabled,
		Store:        cacherepositories.NewRedisStore(redisClient, "user"),
		MaxRequests:  config.CommonLimit,
		Window:       window,
		LimiterType:  constants.RateLimitingGlobalBased,
		ExemptedIPs:  config.ExemptedIPs,
		IncludeRoute: true,
	}

	return map[string]*RateLimiterConfig{
		"token":  tokenLimiter,
		"auth":   authLimiter,
		"user":   userLimiter,
		"common": commonLimiter,
	}
}
