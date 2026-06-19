import pytest
import os
from pathlib import Path
from core.config import (
    parse_simple_yaml,
    _parse_scalar,
    _env_str,
    _env_int,
    _env_bool,
    _hosts_conflict,
    load_config
)

def test_parse_scalar():
    assert _parse_scalar("123") == 123
    assert _parse_scalar("true") is True
    assert _parse_scalar("False") is False
    assert _parse_scalar("'hello'") == "hello"
    assert _parse_scalar('"world"') == "world"
    assert _parse_scalar("string_val") == "string_val"

def test_env_helpers(monkeypatch):
    monkeypatch.setenv("TEST_STR", "hello")
    assert _env_str("TEST_STR", "default") == "hello"
    assert _env_str("MISSING_STR", "default") == "default"

    monkeypatch.setenv("TEST_INT", "42")
    assert _env_int("TEST_INT", 10) == 42
    assert _env_int("MISSING_INT", 10) == 10
    
    monkeypatch.setenv("TEST_BOOL_TRUE", "yes")
    monkeypatch.setenv("TEST_BOOL_FALSE", "0")
    assert _env_bool("TEST_BOOL_TRUE", False) is True
    assert _env_bool("TEST_BOOL_FALSE", True) is False
    assert _env_bool("MISSING_BOOL", True) is True

def test_hosts_conflict():
    assert _hosts_conflict("127.0.0.1", "127.0.0.1") is True
    assert _hosts_conflict("0.0.0.0", "192.168.1.1") is True
    assert _hosts_conflict("192.168.1.1", "::") is True
    assert _hosts_conflict("192.168.1.1", "10.0.0.1") is False

def test_parse_simple_yaml():
    yaml_content = """
host: 0.0.0.0
profile: test_profile
web:
  enabled: true
  port: 8080
services:
  http:
    port: 80
  ssh:
    port: 22
    enabled: false
"""
    result = parse_simple_yaml(yaml_content)
    assert result["host"] == "0.0.0.0"
    assert result["profile"] == "test_profile"
    assert result["web"]["enabled"] is True
    assert result["web"]["port"] == 8080
    assert result["services"]["http"]["port"] == 80
    assert result["services"]["ssh"]["enabled"] is False

def test_load_config_valid_file(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
host: 127.0.0.1
profile: empty
web:
  enabled: true
  port: 8000
services:
  http_linux:
    port: 80
""", encoding="utf-8")
    
    config = load_config(config_file)
    assert config.host == "127.0.0.1"
    assert config.profile == "empty"
    assert config.web.port == 8000
    assert config.services["http_linux"].port == 80
    assert config.services["http_linux"].enabled is True

def test_load_config_port_conflict(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
host: 0.0.0.0
web:
  enabled: true
  port: 8000
services:
  conflict_service:
    port: 8000
    enabled: true
""", encoding="utf-8")
    
    with pytest.raises(ValueError, match="Port conflict detected between web"):
        load_config(config_file)
