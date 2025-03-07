package config

import (
	"time"

	"github.com/spf13/viper"
)

type DatabaseConfig struct {
	URL                string        `mapstructure:"url"`
	MaxOpenConnections int           `mapstructure:"max_open_connections"`
	MaxIdleConnections int           `mapstructure:"max_idle_connections"`
	ConnMaxLifetime    time.Duration `mapstructure:"conn_max_lifetime"`
}

func setDefaultDatabaseConfig(v *viper.Viper) {
	v.SetDefault(DatabaseMaxOpenConnectionsKey, 25)
	v.SetDefault(DatabaseMaxIdleConnectionsKey, 5)
	v.SetDefault(DatabaseConnMaxLifetimeKey, 5*time.Minute)

}
