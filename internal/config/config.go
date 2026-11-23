package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the application configuration loaded from environment variables.
type Config struct {
	DatabricksAccountID    string
	DatabricksAccountsHost string
	ProxyClientID          string
	ProxyClientSecret      string
	ProxyOIDCToken         string
	ProxyOIDCTokenFile     string
	ProxyListenAddr        string
	ConfigFile             string
	CacheTTL               time.Duration
	LogLevel               string
}

// Load reads configuration from the environment and sets defaults where applicable.
func Load() (*Config, error) {
	accountsHost := getEnv("DATABRICKS_ACCOUNTS_HOST", "https://accounts.cloud.databricks.com")
	accountsHost = strings.TrimRight(accountsHost, "/")

	configFile := getEnv("PROXY_CONFIG_FILE", getEnv("CONFIG_FILE", ""))
	if configFile == "" {
		// If default config.yaml exists in the working directory, use it
		if _, err := os.Stat("config.yaml"); err == nil {
			configFile = "config.yaml"
		}
	}

	oidcTokenFile := getEnv("PROXY_OIDC_TOKEN_FILE",
		getEnv("AZURE_FEDERATED_TOKEN_FILE",
			getEnv("AWS_WEB_IDENTITY_TOKEN_FILE", "")))

	cfg := &Config{
		DatabricksAccountID:    os.Getenv("DATABRICKS_ACCOUNT_ID"),
		DatabricksAccountsHost: accountsHost,
		ProxyClientID:          os.Getenv("PROXY_CLIENT_ID"),
		ProxyClientSecret:      os.Getenv("PROXY_CLIENT_SECRET"),
		ProxyOIDCToken:         os.Getenv("PROXY_OIDC_TOKEN"),
		ProxyOIDCTokenFile:     oidcTokenFile,
		ProxyListenAddr:        getEnv("PROXY_LISTEN_ADDR", ":8080"),
		ConfigFile:             configFile,
		LogLevel:               strings.ToUpper(getEnv("LOG_LEVEL", "INFO")),
	}

	ttlSecsStr := getEnv("CACHE_TTL_SECONDS", "60")
	if ttlSecs, err := strconv.Atoi(ttlSecsStr); err == nil && ttlSecs >= 0 {
		cfg.CacheTTL = time.Duration(ttlSecs) * time.Second
	} else {
		cfg.CacheTTL = 60 * time.Second
	}

	return cfg, nil
}

// Validate checks that required configuration values are present.
func (c *Config) Validate() error {
	var missing []string
	if c.ProxyClientID == "" {
		missing = append(missing, "PROXY_CLIENT_ID")
	}
	if c.ProxyClientSecret == "" && c.ProxyOIDCToken == "" && c.ProxyOIDCTokenFile == "" {
		missing = append(missing, "one of PROXY_CLIENT_SECRET, PROXY_OIDC_TOKEN, or PROXY_OIDC_TOKEN_FILE (Workload Identity)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
	return nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
