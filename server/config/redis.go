package config

import "github.com/spf13/viper"

type RedisConfig struct {
	Address            string `mapstructure:"address"`
	MaxIdleConnections int    `mapstructure:"max_idle_connections"`
	Password           string `mapstructure:"password"`
	DB                 int    `mapstructure:"db"`
}

func setDefaultRedisConfig(v *viper.Viper) {
	v.SetDefault(RedisMaxIdleConnectionsKey, 10)
	v.SetDefault(RedisDBKey, 0)
}
