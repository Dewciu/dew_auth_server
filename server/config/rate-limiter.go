package config

import (
	"time"

	"github.com/dewciu/dew_auth_server/server/cacherepositories"
	"github.com/dewciu/dew_auth_server/server/constants"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
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

type RateLimitingConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	TokenLimit  int      `mapstructure:"token_limit"`
	AuthLimit   int      `mapstructure:"auth_limit"`
	LoginLimit  int      `mapstructure:"login_limit"`
	CommonLimit int      `mapstructure:"common_limit"`
	WindowSecs  int      `mapstructure:"window_secs"`
	ExemptedIPs []string `mapstructure:"exempted_ips"`
}

func setDefaultRateLimitingConfig(v *viper.Viper) {
	v.SetDefault(RateLimitEnabledKey, false)
	v.SetDefault(RateLimitTokenLimitKey, 60)
	v.SetDefault(RateLimitAuthLimitKey, 100)
	v.SetDefault(RateLimitLoginLimitKey, 5)
	v.SetDefault(RateLimitCommonLimitKey, 75)
	v.SetDefault(RateLimitWindowSecsKey, 60)
}

func GetRateLimiters(
	config RateLimitingConfig,
	redisClient *redis.Client,
) map[string]*RateLimiterConfig {
	window := time.Duration(config.WindowSecs) * time.Second

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
