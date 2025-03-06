package config

import (
	"strconv"
	"strings"
)

type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCORSConfig returns a default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	}
}

func ParseCORSConfig(
	allowOrigins string,
	allowMethods string,
	allowHeaders string,
	exposeHeaders string,
	allowCredentials string,
	maxAge string,
) *CORSConfig {
	corsConfig := DefaultCORSConfig()

	if allowOrigins != "" {
		corsConfig.AllowOrigins = strings.Split(allowOrigins, ",")
	}

	if allowMethods != "" {
		corsConfig.AllowMethods = strings.Split(allowMethods, ",")
	}

	if allowHeaders != "" {
		corsConfig.AllowHeaders = strings.Split(allowHeaders, ",")
	}

	if exposeHeaders != "" {
		corsConfig.ExposeHeaders = strings.Split(exposeHeaders, ",")
	}

	if allowCredentials == "false" {
		corsConfig.AllowCredentials = false
	}

	if maxAge != "" {
		if val, err := strconv.Atoi(maxAge); err == nil && val >= 0 {
			corsConfig.MaxAge = val
		}
	}

	return corsConfig
}
