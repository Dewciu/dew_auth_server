package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

const (
	// Server keys
	ServerHostKey            = "server.host"
	ServerPortKey            = "server.port"
	ServerTLSCertPathKey     = "server.tls_cert_path"
	ServerTLSKeyPathKey      = "server.tls_key_path"
	ServerShutdownTimeoutKey = "server.shutdown_timeout"
	ServerTemplatePathKey    = "server.template_path"

	// Database keys
	DatabaseURLKey                = "database.url"
	DatabaseMaxOpenConnectionsKey = "database.max_open_connections"
	DatabaseMaxIdleConnectionsKey = "database.max_idle_connections"
	DatabaseConnMaxLifetimeKey    = "database.conn_max_lifetime"

	// Redis keys
	RedisAddressKey            = "redis.address"
	RedisMaxIdleConnectionsKey = "redis.max_idle_connections"
	RedisPasswordKey           = "redis.password"
	RedisDBKey                 = "redis.db"

	// Session keys
	SessionLifetimeKey      = "session.lifetime"
	SessionSigningKeyKey    = "session.signing_key"
	SessionEncryptionKeyKey = "session.encryption_key"

	// OAuth keys
	OAuthAuthCodeLifetimeKey     = "oauth.auth_code_lifetime"
	OAuthAccessTokenLifetimeKey  = "oauth.access_token_lifetime"
	OAuthRefreshTokenLifetimeKey = "oauth.refresh_token_lifetime"

	// Rate limiting keys
	RateLimitEnabledKey     = "rate_limit.enabled"
	RateLimitTokenLimitKey  = "rate_limit.token_limit"
	RateLimitAuthLimitKey   = "rate_limit.auth_limit"
	RateLimitLoginLimitKey  = "rate_limit.login_limit"
	RateLimitCommonLimitKey = "rate_limit.common_limit"
	RateLimitWindowSecsKey  = "rate_limit.window_secs"
	RateLimitExemptedIPsKey = "rate_limit.exempted_ips"

	// CORS keys
	CORSAllowOriginsKey     = "cors.allow_origins"
	CORSAllowMethodsKey     = "cors.allow_methods"
	CORSAllowHeadersKey     = "cors.allow_headers"
	CORSExposeHeadersKey    = "cors.expose_headers"
	CORSAllowCredentialsKey = "cors.allow_credentials"
	CORSMaxAgeKey           = "cors.max_age"

	// Logging keys
	LoggingLevelKey      = "logging.level"
	LoggingFormatKey     = "logging.format"
	LoggingFileKey       = "logging.file"
	LoggingEnableJSONKey = "logging.enable_json"
)

type Config struct {
	Server    ServerConfig       `mapstructure:"server"`
	Database  DatabaseConfig     `mapstructure:"database"`
	Redis     RedisConfig        `mapstructure:"redis"`
	Session   SessionConfig      `mapstructure:"session"`
	OAuth     OAuthConfig        `mapstructure:"oauth"`
	RateLimit RateLimitingConfig `mapstructure:"rate_limit"`
	CORS      CORSConfig         `mapstructure:"cors"`
	Logging   LoggingConfig      `mapstructure:"logging"`
}

func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			// It's okay if config file doesn't exist, we'll use environment variables
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	v.SetEnvPrefix("DEW_AUTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	bindEnvVariables(v)

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	setDefaultServerConfig(v)
	setDefaultDatabaseConfig(v)
	setDefaultRedisConfig(v)
	setDefaultSessionConfig(v)
	setDefaultOAuthConfig(v)
	setDefaultRateLimitingConfig(v)
	setDefaultCORSConfig(v)
	setDefaultLoggingConfig(v)
}

func bindEnvVariables(v *viper.Viper) {
	for _, key := range []string{
		ServerHostKey,
		ServerPortKey,
		ServerTLSCertPathKey,
		ServerTLSKeyPathKey,
		ServerShutdownTimeoutKey,
		ServerTemplatePathKey,
		DatabaseURLKey,
		DatabaseMaxOpenConnectionsKey,
		DatabaseMaxIdleConnectionsKey,
		DatabaseConnMaxLifetimeKey,
		RedisAddressKey,
		RedisMaxIdleConnectionsKey,
		RedisPasswordKey,
		RedisDBKey,
		SessionLifetimeKey,
		SessionSigningKeyKey,
		SessionEncryptionKeyKey,
		OAuthAuthCodeLifetimeKey,
		OAuthAccessTokenLifetimeKey,
		OAuthRefreshTokenLifetimeKey,
		RateLimitEnabledKey,
		RateLimitTokenLimitKey,
		RateLimitAuthLimitKey,
		RateLimitLoginLimitKey,
		RateLimitCommonLimitKey,
		RateLimitWindowSecsKey,
		RateLimitExemptedIPsKey,
		CORSAllowOriginsKey,
		CORSAllowMethodsKey,
		CORSAllowHeadersKey,
		CORSExposeHeadersKey,
		CORSAllowCredentialsKey,
		CORSMaxAgeKey,
		LoggingLevelKey,
		LoggingFormatKey,
		LoggingFileKey,
		LoggingEnableJSONKey,
	} {
		v.BindEnv(key)
	}
}

func validateConfig(config *Config) error {
	// Add validation logic here
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	// Validate other required fields
	if config.Database.URL == "" {
		return fmt.Errorf("database URL is required")
	}

	if config.Redis.Address == "" {
		return fmt.Errorf("redis address is required")
	}

	// Validate token lifetimes
	if config.OAuth.AuthCodeLifetime <= 0 {
		return fmt.Errorf("auth code lifetime must be positive")
	}

	if config.OAuth.AccessTokenLifetime <= 0 {
		return fmt.Errorf("access token lifetime must be positive")
	}

	if config.OAuth.RefreshTokenLifetime <= 0 {
		return fmt.Errorf("refresh token lifetime must be positive")
	}

	return nil
}
