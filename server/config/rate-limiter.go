package config

import (
	"strconv"
	"strings"
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

func ParseRateLimitConfig(
	enabled string,
	tokenLimit string,
	authLimit string,
	loginLimit string,
	commonLimit string,
	windowSecs string,
	exemptedIPs string,
) ServerRateLimitingConfig {
	config := ServerRateLimitingConfig{
		Enabled:      false,
		TokenLimit:   60,
		AuthLimit:    100,
		LoginLimit:   5,
		CommonLimit:  75,
		WindowInSecs: 60,
		ExemptedIPs:  []string{},
	}

	// Parse enabled flag
	if enabled == "true" {
		config.Enabled = true
	}

	// Parse limits
	if val, err := strconv.Atoi(tokenLimit); err == nil && val > 0 {
		config.TokenLimit = val
	}

	if val, err := strconv.Atoi(authLimit); err == nil && val > 0 {
		config.AuthLimit = val
	}

	if val, err := strconv.Atoi(loginLimit); err == nil && val > 0 {
		config.LoginLimit = val
	}

	if val, err := strconv.Atoi(commonLimit); err == nil && val > 0 {
		config.CommonLimit = val
	}

	if val, err := strconv.Atoi(windowSecs); err == nil && val > 0 {
		config.WindowInSecs = val
	}

	if exemptedIPs != "" {
		config.ExemptedIPs = strings.Split(exemptedIPs, ",")
	}

	return config
}
