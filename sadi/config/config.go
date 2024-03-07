package config

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
)

type Config struct {
	App      AppConfig
	Database DatabaseConfig
	Kafka    KafkaConfig
}

type AppConfig struct {
	Environment string
}

type DatabaseConfig struct {
	Host               string
	Port               int
	User               string
	Password           string
	DbName             string
	SslMode            string
	MaxOpenConnections int
	MaxIdleConnections int
	ConnMaxLifetime    int
}

type KafkaConfig struct {
	Brokers []string
	Topics  []string
	GroupID string
}

type configValidator func(*Config) error

var validators = []configValidator{
	func(cfg *Config) error {
		return validateEnvironment(cfg.App.Environment)
	},
	func(cfg *Config) error {
		return validatePort(cfg.Database.Port)
	},
}

var internalConfig *Config

func InitConfig() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()

	viper.SetDefault("app.environment", "prod")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("read config failed: %v", err)
	}
	if err := viper.Unmarshal(&internalConfig); err != nil {
		log.Fatalf("unmarshal config failed: %v", err)
	}

	for _, validator := range validators {
		if err := validator(internalConfig); err != nil {
			log.Fatalf("configuration error: %v", err)
		}
	}
}

func Kafka() *KafkaConfig {
	return &internalConfig.Kafka
}

func Database() *DatabaseConfig {
	return &internalConfig.Database
}

func App() *AppConfig {
	return &internalConfig.App
}

// Validators
func validateEnvironment(env string) error {
	validEnvironments := map[string]bool{"dev": true, "prod": true}
	if _, isValid := validEnvironments[env]; !isValid {
		return fmt.Errorf("invalid environment '%s': the environment must be either 'dev' or 'prod'", env)
	}
	return nil
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number %d: port must be between 1 and 65535", port)
	}
	return nil
}
