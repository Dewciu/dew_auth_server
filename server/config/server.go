package config

import (
	"time"

	"github.com/spf13/viper"
)

type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	TLSCertPath     string        `mapstructure:"tls_cert_path"`
	TLSKeyPath      string        `mapstructure:"tls_key_path"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	TemplatePath    string        `mapstructure:"template_path"`
}

func setDefaultServerConfig(v *viper.Viper) {
	v.SetDefault(ServerHostKey, "0.0.0.0")
	v.SetDefault(ServerPortKey, 8050)
	v.SetDefault(ServerShutdownTimeoutKey, 10*time.Second)
	v.SetDefault(ServerTemplatePathKey, "./server/controllers/templates")
}
