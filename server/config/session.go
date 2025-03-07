package config

import (
	"time"

	"github.com/spf13/viper"
)

type SessionConfig struct {
	Lifetime      time.Duration `mapstructure:"lifetime"`
	SigningKey    string        `mapstructure:"signing_key"`
	EncryptionKey string        `mapstructure:"encryption_key"`
}

func setDefaultSessionConfig(v *viper.Viper) {
	v.SetDefault(SessionLifetimeKey, 24*time.Hour)
}
