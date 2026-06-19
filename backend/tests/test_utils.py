import pytest
from web.utils import _format_duration, _parse_request_line, _parse_cookies, _normalize_role

def test_format_duration():
    assert _format_duration(0) == "0s"
    assert _format_duration(61) == "1m 1s"
    assert _format_duration(3665) == "1h 1m 5s"
    assert _format_duration(90061) == "1d 1h 1m 1s"

def test_parse_request_line():
    method, target, http_ver = _parse_request_line("GET /api/test HTTP/1.1")
    assert method == "GET"
    assert target == "/api/test"
    assert http_ver == "HTTP/1.1"

    method, target, http_ver = _parse_request_line("INVALID")
    assert method == "GET"
    assert target == "/"
    assert http_ver == "HTTP/1.1"

def test_parse_cookies():
    cookies = _parse_cookies("session_id=12345; user=admin")
    assert cookies == {"session_id": "12345", "user": "admin"}
    assert _parse_cookies("") == {}

def test_normalize_role():
    assert _normalize_role("ADMIN") == "admin"
    assert _normalize_role("viewer") == "viewer"
    assert _normalize_role("hacker") == "viewer"
