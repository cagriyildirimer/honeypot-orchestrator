package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	yamlContent := `
host: "127.0.0.1"
profile: "windows_server"
logging:
  path: "logs/events.jsonl"
web:
  enabled: true
  host: "127.0.0.1"
  port: 8000
auth:
  username: "admin"
  password: "testpassword"
threat_intel:
  abuseipdb_key: "test_abuse_key"
  greynoise_key: "test_grey_key"
services:
  http_windows:
    enabled: true
    host: "127.0.0.1"
    port: 80
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected Host '127.0.0.1', got '%s'", cfg.Host)
	}
	if cfg.Profile != "windows_server" {
		t.Errorf("Expected Profile 'windows_server', got '%s'", cfg.Profile)
	}
	if cfg.Auth.Username != "admin" {
		t.Errorf("Expected Auth.Username 'admin', got '%s'", cfg.Auth.Username)
	}
	if cfg.Auth.Password != "testpassword" {
		t.Errorf("Expected Auth.Password 'testpassword', got '%s'", cfg.Auth.Password)
	}
	if !cfg.Services["http_windows"].Enabled {
		t.Errorf("Expected http_windows service to be enabled")
	}
}
