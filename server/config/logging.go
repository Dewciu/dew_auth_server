package config

import "github.com/spf13/viper"

type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	File       string `mapstructure:"file"`
	EnableJSON bool   `mapstructure:"enable_json"`
}

func setDefaultLoggingConfig(v *viper.Viper) {
	v.SetDefault(LoggingLevelKey, "info")
	v.SetDefault(LoggingFormatKey, "text")
	v.SetDefault(LoggingEnableJSONKey, false)
}
