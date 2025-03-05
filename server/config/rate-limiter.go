package config

import (
	"time"

	"github.com/dewciu/dew_auth_server/server/cacherepositories"
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
