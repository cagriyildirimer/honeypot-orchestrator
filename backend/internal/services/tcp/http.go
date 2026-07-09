package tcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
	"honeypot-orchestrator/backend/internal/services"
)

type HTTPHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
}

func NewHTTPHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *HTTPHoneypot {
	h := &HTTPHoneypot{
		profile: initialProfile,
	}

	h.baseService = services.NewBaseTCPService(name, host, port, el, ds, h.handleClient)
	return h
}

func (h *HTTPHoneypot) Name() string {
	return h.baseService.Name()
}

func (h *HTTPHoneypot) Port() int {
	return h.baseService.Port()
}

func (h *HTTPHoneypot) Proto() string {
	return h.baseService.Proto()
}

func (h *HTTPHoneypot) IsRunning() bool {
	return h.baseService.IsRunning()
}

func (h *HTTPHoneypot) Start(ctx context.Context) error {
	return h.baseService.Start(ctx)
}

func (h *HTTPHoneypot) Stop() error {
	return h.baseService.Stop()
}

func (h *HTTPHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	h.profile = prof
}

func (h *HTTPHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	reader := bufio.NewReader(conn)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	requestLine = strings.TrimSpace(requestLine)

	parts := strings.Split(requestLine, " ")
	method := "GET"
	path := "/"
	if len(parts) >= 2 {
		method = strings.ToUpper(parts[0])
		path = parts[1]
	}

	headers := make(map[string]string)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(headerParts[0]))] = strings.TrimSpace(headerParts[1])
		}
	}

	var body []byte
	contentLengthVal := headers["content-length"]
	if contentLengthVal != "" {
		contentLength, err := strconv.Atoi(contentLengthVal)
		if err == nil && contentLength > 0 {
			if contentLength > 8192 {
				contentLength = 8192
			}
			body = make([]byte, contentLength)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = io.ReadFull(reader, body)
			if err != nil && err != io.ErrUnexpectedEOF {
				return err
			}
		}
	}

	var username, password, domain string
	if method == "POST" && len(body) > 0 {
		var jsonMap map[string]interface{}
		if err := json.Unmarshal(body, &jsonMap); err == nil {
			if u, ok := jsonMap["username"].(string); ok {
				username = u
			}
			if p, ok := jsonMap["password"].(string); ok {
				password = p
			}
			if d, ok := jsonMap["domain"].(string); ok {
				domain = d
			}
		} else {
			if values, err := url.ParseQuery(string(body)); err == nil {
				username = values.Get("username")
				password = values.Get("password")
				domain = values.Get("domain")
			}
		}

		if username != "" || password != "" {
			if domain == "" {
				domain = "WORKGROUP"
			}
			h.baseService.LogEvent("credential_attempt", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"username": username,
				"password": password,
				"domain":   domain,
				"summary":  fmt.Sprintf("Captured HTTP login attempt: %s\\%s", domain, username),
			})
		}
	}

	userAgent := headers["user-agent"]
	hostHeader := headers["host"]
	h.baseService.LogEvent("request", map[string]interface{}{
		"src_ip":     srcIP,
		"src_port":   srcPort,
		"method":     method,
		"path":       path,
		"user_agent": userAgent,
		"host":       hostHeader,
		"summary":    fmt.Sprintf("HTTP %s %s from %s", method, path, srcIP),
	})

	httpProf := h.profile.HTTP

	var responseBody bytes.Buffer
	responseBody.WriteString("HTTP/1.1 " + httpProf.DefaultStatus + "\r\n")
	responseBody.WriteString("Server: " + httpProf.ServerHeader + "\r\n")
	responseBody.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	responseBody.WriteString("Content-Length: " + strconv.Itoa(len(httpProf.BodyHTML)) + "\r\n")
	responseBody.WriteString("Connection: close\r\n")
	responseBody.WriteString("\r\n")
	responseBody.WriteString(httpProf.BodyHTML)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(responseBody.Bytes())
	return err
}

func init() {
	services.Registry["http"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewHTTPHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *HTTPHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
