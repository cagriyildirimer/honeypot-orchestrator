package config

import (
	"gopkg.in/yaml.v3"
	"os"
	"strconv"
	"strings"
)

type ServiceConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
}

type LoggingConfig struct {
	Path string `yaml:"path"`
}

type WebConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
}

type AuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ThreatIntelConfig struct {
	AbuseIPDBKey string `yaml:"abuseipdb_key"`
	GreyNoiseKey string `yaml:"greynoise_key"`
}

type RawYamlConfig struct {
	Host        string                   `yaml:"host"`
	Profile     string                   `yaml:"profile"`
	Logging     LoggingConfig            `yaml:"logging"`
	Web         WebConfig                `yaml:"web"`
	Auth        AuthConfig               `yaml:"auth"`
	ThreatIntel ThreatIntelConfig        `yaml:"threat_intel"`
	Services    map[string]ServiceConfig `yaml:"services"`
}

type AppConfig struct {
	Host        string
	Profile     string
	DBURL       string
	Logging     LoggingConfig
	Web         WebConfig
	Auth        AuthConfig
	ThreatIntel ThreatIntelConfig
	Services    map[string]ServiceConfig
}

func getEnvStr(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return fallback
	}
	return b
}

func getEnvInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return i
}

func serviceEnvKey(serviceName, field string) string {
	upperService := strings.ToUpper(serviceName)
	return "HONEYPOT_SERVICE_" + upperService + "_" + field
}

func LoadConfig(configPath string) (*AppConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var raw RawYamlConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	baseHost := getEnvStr("HONEYPOT_HOST", raw.Host)
	if baseHost == "" {
		baseHost = "127.0.0.1"
	}

	profile := getEnvStr("HONEYPOT_PROFILE", raw.Profile)
	if profile == "" {
		profile = "windows_server"
	}

	dbURL := getEnvStr("HONEYPOT_DB_URL", "postgresql://honeypot:honeypot_password@localhost:5432/honeypot")
	dbURL = strings.Replace(dbURL, "postgresql+asyncpg://", "postgresql://", 1)
	dbURL = strings.Replace(dbURL, "postgres+asyncpg://", "postgresql://", 1)

	logPath := getEnvStr("HONEYPOT_LOG_PATH", raw.Logging.Path)
	if logPath == "" {
		logPath = "logs/events.jsonl"
	}

	webEnabled := getEnvBool("HONEYPOT_WEB_ENABLED", raw.Web.Enabled)
	webHost := getEnvStr("HONEYPOT_WEB_HOST", raw.Web.Host)
	if webHost == "" {
		webHost = baseHost
	}
	webPort := getEnvInt("HONEYPOT_WEB_PORT", raw.Web.Port)
	if webPort == 0 {
		webPort = 8000
	}

	authUsername := getEnvStr("HONEYPOT_AUTH_USERNAME", raw.Auth.Username)
	if authUsername == "" {
		authUsername = "admin"
	}
	authPassword := getEnvStr("HONEYPOT_AUTH_PASSWORD", raw.Auth.Password)
	if authPassword == "" {
		authPassword = "admin123"
	}

	abuseKey := getEnvStr("HONEYPOT_TI_ABUSEIPDB_KEY", raw.ThreatIntel.AbuseIPDBKey)
	greyKey := getEnvStr("HONEYPOT_TI_GREYNOISE_KEY", raw.ThreatIntel.GreyNoiseKey)

	services := make(map[string]ServiceConfig)
	for name, val := range raw.Services {
		svcHost := getEnvStr(serviceEnvKey(name, "HOST"), val.Host)
		if svcHost == "" {
			svcHost = baseHost
		}
		services[name] = ServiceConfig{
			Enabled: getEnvBool(serviceEnvKey(name, "ENABLED"), val.Enabled),
			Host:    svcHost,
			Port:    getEnvInt(serviceEnvKey(name, "PORT"), val.Port),
		}
	}

	return &AppConfig{
		Host:    baseHost,
		Profile: profile,
		DBURL:   dbURL,
		Logging: LoggingConfig{Path: logPath},
		Web: WebConfig{
			Enabled: webEnabled,
			Host:    webHost,
			Port:    webPort,
		},
		Auth: AuthConfig{
			Username: authUsername,
			Password: authPassword,
		},
		ThreatIntel: ThreatIntelConfig{
			AbuseIPDBKey: abuseKey,
			GreyNoiseKey: greyKey,
		},
		Services: services,
	}, nil
}
