package config

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

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

func ConfigureLogging(logConfig LoggingConfig) {
	// Set log level
	level, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	// Configure log format
	if logConfig.EnableJSON {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	// Configure log output
	if logConfig.File != "" {
		file, err := os.OpenFile(logConfig.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			logrus.SetOutput(file)
		} else {
			logrus.WithError(err).Error("Failed to log to file, using default stderr")
		}
	}
}
