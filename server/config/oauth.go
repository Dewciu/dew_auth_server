package config

import (
	"time"

	"github.com/spf13/viper"
)

type OAuthConfig struct {
	AuthCodeLifetime     time.Duration `mapstructure:"auth_code_lifetime"`
	AccessTokenLifetime  time.Duration `mapstructure:"access_token_lifetime"`
	RefreshTokenLifetime time.Duration `mapstructure:"refresh_token_lifetime"`
}

func setDefaultOAuthConfig(v *viper.Viper) {
	v.SetDefault(OAuthAuthCodeLifetimeKey, 10*time.Minute)
	v.SetDefault(OAuthAccessTokenLifetimeKey, time.Hour)
	v.SetDefault(OAuthRefreshTokenLifetimeKey, 30*24*time.Hour)
}
