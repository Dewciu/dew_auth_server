package config

import (
	"fmt"
	"strings"
	"time"

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
	Server struct {
		Host            string        `mapstructure:"host"`
		Port            int           `mapstructure:"port"`
		TLSCertPath     string        `mapstructure:"tls_cert_path"`
		TLSKeyPath      string        `mapstructure:"tls_key_path"`
		ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
		TemplatePath    string        `mapstructure:"template_path"`
	} `mapstructure:"server"`

	Database struct {
		URL                string        `mapstructure:"url"`
		MaxOpenConnections int           `mapstructure:"max_open_connections"`
		MaxIdleConnections int           `mapstructure:"max_idle_connections"`
		ConnMaxLifetime    time.Duration `mapstructure:"conn_max_lifetime"`
	} `mapstructure:"database"`

	Redis struct {
		Address            string `mapstructure:"address"`
		MaxIdleConnections int    `mapstructure:"max_idle_connections"`
		Password           string `mapstructure:"password"`
		DB                 int    `mapstructure:"db"`
	} `mapstructure:"redis"`

	Session struct {
		Lifetime      time.Duration `mapstructure:"lifetime"`
		SigningKey    string        `mapstructure:"signing_key"`
		EncryptionKey string        `mapstructure:"encryption_key"`
	} `mapstructure:"session"`

	OAuth struct {
		AuthCodeLifetime     time.Duration `mapstructure:"auth_code_lifetime"`
		AccessTokenLifetime  time.Duration `mapstructure:"access_token_lifetime"`
		RefreshTokenLifetime time.Duration `mapstructure:"refresh_token_lifetime"`
	} `mapstructure:"oauth"`

	RateLimit RateLimitingConfig `mapstructure:"rate_limit"`

	CORS CORSConfig `mapstructure:"cors"`

	Logging struct {
		Level      string `mapstructure:"level"`
		Format     string `mapstructure:"format"`
		File       string `mapstructure:"file"`
		EnableJSON bool   `mapstructure:"enable_json"`
	} `mapstructure:"logging"`
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
	// Server defaults
	v.SetDefault(ServerHostKey, "0.0.0.0")
	v.SetDefault(ServerPortKey, 8050)
	v.SetDefault(ServerShutdownTimeoutKey, 10*time.Second)
	v.SetDefault(ServerTemplatePathKey, "./server/controllers/templates")

	// Database defaults
	v.SetDefault(DatabaseMaxOpenConnectionsKey, 25)
	v.SetDefault(DatabaseMaxIdleConnectionsKey, 5)
	v.SetDefault(DatabaseConnMaxLifetimeKey, 5*time.Minute)

	// Redis defaults
	v.SetDefault(RedisMaxIdleConnectionsKey, 10)
	v.SetDefault(RedisDBKey, 0)

	// Session defaults
	v.SetDefault(SessionLifetimeKey, 24*time.Hour)

	// OAuth defaults
	v.SetDefault(OAuthAuthCodeLifetimeKey, 10*time.Minute)
	v.SetDefault(OAuthAccessTokenLifetimeKey, time.Hour)
	v.SetDefault(OAuthRefreshTokenLifetimeKey, 30*24*time.Hour)

	// Rate limiting defaults
	setDefaultRateLimitingConfig(v)

	// CORS defaults
	setDefaultCORSConfig(v)

	// Logging defaults
	v.SetDefault(LoggingLevelKey, "info")
	v.SetDefault(LoggingFormatKey, "text")
	v.SetDefault(LoggingEnableJSONKey, false)
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
