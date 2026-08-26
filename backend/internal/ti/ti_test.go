package ti

import (
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.100", true},
		{"172.16.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		got := IsPrivateIP(tt.ip)
		if got != tt.expected {
			t.Errorf("IsPrivateIP(%q) = %v; want %v", tt.ip, got, tt.expected)
		}
	}
}

func TestMatchCloudProvider(t *testing.T) {
	provider := MatchCloudProvider("3.0.0.1")
	if provider != "AWS" {
		t.Errorf("MatchCloudProvider('3.0.0.1') = %q; want 'AWS'", provider)
	}
}
