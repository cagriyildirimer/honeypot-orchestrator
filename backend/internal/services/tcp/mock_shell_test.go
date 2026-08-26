package tcp

import (
	"testing"
)

func TestResolveWindowsPath(t *testing.T) {
	tests := []struct {
		current  string
		target   string
		expected string
	}{
		{"C:\\Windows", "system32", "C:\\Windows\\system32"},
		{"C:\\Windows\\system32", "..", "C:\\Windows"},
		{"C:\\Users\\admin", "C:\\Program Files", "C:\\Program Files"},
		{"C:\\Users\\admin", "/etc", "C:\\etc"},
	}

	for _, tt := range tests {
		got := ResolveWindowsPath(tt.current, tt.target)
		if got != tt.expected {
			t.Errorf("ResolveWindowsPath(%q, %q) = %q; want %q", tt.current, tt.target, got, tt.expected)
		}
	}
}

func TestResolveLinuxPath(t *testing.T) {
	tests := []struct {
		current  string
		target   string
		expected string
	}{
		{"/var/log", "nginx", "/var/log/nginx"},
		{"/var/log/nginx", "..", "/var/log"},
		{"/home/user", "/etc/passwd", "/etc/passwd"},
	}

	for _, tt := range tests {
		got := ResolveLinuxPath(tt.current, tt.target)
		if got != tt.expected {
			t.Errorf("ResolveLinuxPath(%q, %q) = %q; want %q", tt.current, tt.target, got, tt.expected)
		}
	}
}

func TestGetMockFileContent(t *testing.T) {
	content := GetMockFileContent("/etc/passwd")
	if content == "" || content == "Erişim reddedildi veya dosya okunamıyor.\r\n" {
		t.Errorf("Expected valid passwd mock content, got %q", content)
	}
}
