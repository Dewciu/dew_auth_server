package config

import "github.com/spf13/viper"

type CORSConfig struct {
	AllowOrigins     []string `mapstructure:"allow_origins"`
	AllowMethods     []string `mapstructure:"allow_methods"`
	AllowHeaders     []string `mapstructure:"allow_headers"`
	ExposeHeaders    []string `mapstructure:"expose_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

func setDefaultCORSConfig(v *viper.Viper) {
	v.SetDefault(CORSAllowOriginsKey, []string{"*"})
	v.SetDefault(CORSAllowMethodsKey, []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	v.SetDefault(CORSAllowHeadersKey, []string{"Origin", "Content-Type", "Accept", "Authorization"})
	v.SetDefault(CORSExposeHeadersKey, []string{"Content-Length", "Content-Type"})
	v.SetDefault(CORSAllowCredentialsKey, true)
	v.SetDefault(CORSMaxAgeKey, 86400)
}
