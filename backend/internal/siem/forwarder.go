package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/database"
)

type SiemTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "udp", "tcp", "http"
	Scope    string `json:"scope"`    // "all", "alerts"
}

type Forwarder struct {
	db         *database.DB
	configs    []SiemTarget
	mu         sync.RWMutex
	tcpConns   map[string]net.Conn
	httpClient *http.Client
}

func NewForwarder(db *database.DB) *Forwarder {
	return &Forwarder{
		db:       db,
		tcpConns: make(map[string]net.Conn),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (f *Forwarder) LoadConfig(configJSON string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var rawConfigs []SiemTarget
	type RawRequest struct {
		Configs []SiemTarget `json:"configs"`
	}

	if err := json.Unmarshal([]byte(configJSON), &rawConfigs); err != nil {
		var req RawRequest
		if err2 := json.Unmarshal([]byte(configJSON), &req); err2 != nil {
			return fmt.Errorf("invalid config json: %w", err2)
		}
		rawConfigs = req.Configs
	}

	var parsed []SiemTarget
	for i, c := range rawConfigs {
		if c.Host == "" {
			continue
		}
		id := c.ID
		if id == "" {
			id = fmt.Sprintf("siem-%d", time.Now().UnixNano()+int64(i))
		}
		proto := strings.ToLower(c.Protocol)
		if proto != "udp" && proto != "tcp" && proto != "http" {
			proto = "udp"
		}
		scope := strings.ToLower(c.Scope)
		if scope != "all" && scope != "alerts" {
			scope = "all"
		}
		port := c.Port
		if port <= 0 || port > 65535 {
			port = 514
		}
		parsed = append(parsed, SiemTarget{
			ID:       id,
			Name:     c.Name,
			Enabled:  c.Enabled,
			Host:     c.Host,
			Port:     port,
			Protocol: proto,
			Scope:    scope,
		})
	}

	// Close TCP connections that are no longer active
	activeKeys := make(map[string]bool)
	for _, c := range parsed {
		if c.Enabled && c.Protocol == "tcp" {
			key := fmt.Sprintf("%s:%s:%d", c.ID, c.Host, c.Port)
			activeKeys[key] = true
		}
	}

	for key, conn := range f.tcpConns {
		if !activeKeys[key] {
			conn.Close()
			delete(f.tcpConns, key)
		}
	}

	f.configs = parsed
	return nil
}

func (f *Forwarder) Sync(ctx context.Context) {
	val, err := f.db.GetSystemSetting(ctx, "siem_config")
	if err == nil && val != "" {
		_ = f.LoadConfig(val)
	}
}

func (f *Forwarder) Forward(evt *database.Event) {
	f.mu.RLock()
	configs := f.configs
	f.mu.RUnlock()

	for _, c := range configs {
		if !c.Enabled || c.Host == "" {
			continue
		}

		if c.Scope == "alerts" {
			critical := false
			criticalTypes := []string{"login_attempt", "exploit_attempt", "command_execution"}
			for _, ct := range criticalTypes {
				if evt.EventType == ct {
					critical = true
					break
				}
			}
			if !critical {
				continue
			}
		}

		go func(target SiemTarget) {
			if err := f.ForwardTo(target, evt); err != nil {
				log.Printf("[SIEM] Forward to %s failed: %v\n", target.Name, err)
			}
		}(c)
	}
}

func (f *Forwarder) ForwardTo(target SiemTarget, evt *database.Event) error {
	payloadBytes, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	payloadBytes = append(payloadBytes, '\n')

	host := target.Host
	port := target.Port
	protocol := target.Protocol

	if protocol == "udp" {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("udp", addr, 3*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write(payloadBytes)
		return err
	} else if protocol == "tcp" {
		key := fmt.Sprintf("%s:%s:%d", target.ID, host, port)
		var writeErr error
		maxAttempts := 3

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			f.mu.Lock()
			conn := f.tcpConns[key]
			f.mu.Unlock()

			if conn != nil {
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, writeErr = conn.Write(payloadBytes)
				if writeErr == nil {
					return nil // Success!
				}
				// Write failed. Close connection and delete from map.
				conn.Close()
				f.mu.Lock()
				if f.tcpConns[key] == conn {
					delete(f.tcpConns, key)
				}
				f.mu.Unlock()
			}

			// Connection is nil or writing failed, try to reconnect
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			var dialErr error
			conn, dialErr = net.DialTimeout("tcp", addr, 5*time.Second)
			if dialErr != nil {
				writeErr = dialErr
			} else {
				f.mu.Lock()
				f.tcpConns[key] = conn
				f.mu.Unlock()

				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, writeErr = conn.Write(payloadBytes)
				if writeErr == nil {
					return nil // Success!
				}
				conn.Close()
				f.mu.Lock()
				if f.tcpConns[key] == conn {
					delete(f.tcpConns, key)
				}
				f.mu.Unlock()
			}

			if attempt < maxAttempts {
				time.Sleep(time.Duration(attempt) * time.Second) // 1s, 2s backoff
			}
		}
		return fmt.Errorf("failed to send to TCP SIEM target after %d attempts: %w", maxAttempts, writeErr)
	} else if protocol == "http" {
		urlStr := host
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			urlStr = fmt.Sprintf("http://%s", net.JoinHostPort(host, strconv.Itoa(port)))
		} else {
			parsed, err := url.Parse(host)
			if err == nil && parsed.Port() == "" {
				parsed.Host = net.JoinHostPort(parsed.Hostname(), strconv.Itoa(port))
				urlStr = parsed.String()
			}
		}

		// Re-use already marshaled payload bytes (excluding the trailing newline)
		reqBytes := payloadBytes
		if len(reqBytes) > 0 && reqBytes[len(reqBytes)-1] == '\n' {
			reqBytes = reqBytes[:len(reqBytes)-1]
		}

		req, err := http.NewRequest("POST", urlStr, bytes.NewReader(reqBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := f.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("http server returned status: %d", resp.StatusCode)
		}
		return nil
	}

	return fmt.Errorf("unknown protocol: %s", protocol)
}
