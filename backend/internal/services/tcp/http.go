package tcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const fortigateLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiGate - Login</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1537 1101'%3E%3Cpath fill-rule='evenodd' fill='%23ee3124' d='M.2 408.6h434.5v285.8H.2zM554.9 2.3h426.8v285.8H554.9zm0 811h426.8v285.8H554.9zm545.4-404.7h436v285.8h-436zM434.7 2.3v287.3H.2v-32.4C17.2 127.4 88 25.4 178.9 2.3zm1.6 811v285.8H168.2C81.9 1071.3 15.7 972.4.3 848.8v-35.5zm1100-526.8h-436V.7h257.3c90.9 24.7 161.8 126.7 178.7 254.9zm-436 814.1V814.9h436v35.5c-16.9 123.6-83.2 220.9-167.9 250.2z'/%3E%3C/svg%3E">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #e2e2e2;
            color: #333333;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background-color: #ededed;
            border-radius: 6px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.12);
            width: 360px;
            overflow: hidden;
        }
        .header-bar {
            background-color: #418c59;
            height: 52px;
            padding: 0 16px;
            display: flex;
            align-items: center;
        }
        .header-logo {
            display: flex;
            align-items: center;
        }
        .card-body {
            padding: 24px;
        }
        .form-group {
            margin-bottom: 12px;
            position: relative;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px 14px;
            background-color: #d8d8d8;
            border: 1px solid #cecece;
            border-radius: 4px;
            color: #333333;
            font-size: 13.5px;
            outline: none;
            transition: border-color 0.2s, background-color 0.2s;
        }
        input[type="text"]::placeholder, input[type="password"]::placeholder {
            color: #888888;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: #418c59;
            background-color: #dedede;
        }
        .password-wrapper {
            position: relative;
        }
        .eye-btn {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0.6;
        }
        .eye-btn:hover {
            opacity: 1;
        }
        .btn-submit {
            width: 100%;
            padding: 10px;
            background-color: #418c59;
            border: none;
            border-radius: 4px;
            color: #ffffff;
            font-weight: 600;
            font-size: 13.5px;
            cursor: pointer;
            transition: background-color 0.2s;
            margin-top: 6px;
        }
        .btn-submit:hover {
            background-color: #37774b;
        }
        .alert-error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12.5px;
            margin-bottom: 14px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="header-bar">
            <div class="header-logo">
                <svg viewBox="0 0 1537 1101" width="32" height="23" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" fill="white" d="M.2 408.6h434.5v285.8H.2zM554.9 2.3h426.8v285.8H554.9zm0 811h426.8v285.8H554.9zm545.4-404.7h436v285.8h-436zM434.7 2.3v287.3H.2v-32.4C17.2 127.4 88 25.4 178.9 2.3zm1.6 811v285.8H168.2C81.9 1071.3 15.7 972.4.3 848.8v-35.5zm1100-526.8h-436V.7h257.3c90.9 24.7 161.8 126.7 178.7 254.9zm-436 814.1V814.9h436v35.5c-16.9 123.6-83.2 220.9-167.9 250.2z"/>
                </svg>
            </div>
        </div>
        <div class="card-body">
            <div id="errorBox" class="alert-error">
                Authentication failed. Invalid username or password.
            </div>
            <form method="POST" action="/remote/logincheck" id="loginForm">
                <div class="form-group">
                    <input type="text" id="username" name="username" placeholder="Username" required autocomplete="username" autofocus>
                </div>
                <div class="form-group password-wrapper">
                    <input type="password" id="credential" name="credential" placeholder="Password" required autocomplete="current-password">
                    <button type="button" class="eye-btn" onclick="togglePassword()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                    </button>
                </div>
                <button type="submit" class="btn-submit">Login</button>
            </form>
        </div>
    </div>
    <script>
        if (window.location.search.includes('error=1') || window.location.search.includes('invalid=1')) {
            document.getElementById('errorBox').style.display = 'block';
        }
        function togglePassword() {
            var pwd = document.getElementById('credential');
            if (pwd.type === 'password') {
                pwd.type = 'text';
            } else {
                pwd.type = 'password';
            }
        }
    </script>
</body>
</html>`

	var username, password, domain string
	if method == "POST" && len(body) > 0 {
		var jsonMap map[string]interface{}
		if err := json.Unmarshal(body, &jsonMap); err == nil {
			if u, ok := jsonMap["username"].(string); ok {
				username = u
			}
			if u, ok := jsonMap["user"].(string); ok && username == "" {
				username = u
			}
			if u, ok := jsonMap["name"].(string); ok && username == "" {
				username = u
			}
			if p, ok := jsonMap["password"].(string); ok {
				password = p
			}
			if p, ok := jsonMap["credential"].(string); ok && password == "" {
				password = p
			}
			if p, ok := jsonMap["pass"].(string); ok && password == "" {
				password = p
			}
			if d, ok := jsonMap["domain"].(string); ok {
				domain = d
			}
		} else {
			if values, err := url.ParseQuery(string(body)); err == nil {
				if u := values.Get("username"); u != "" {
					username = u
				}
				if u := values.Get("user"); u != "" && username == "" {
					username = u
				}
				if u := values.Get("name"); u != "" && username == "" {
					username = u
				}
				if p := values.Get("password"); p != "" {
					password = p
				}
				if p := values.Get("credential"); p != "" && password == "" {
					password = p
				}
				if p := values.Get("pass"); p != "" && password == "" {
					password = p
				}
				if d := values.Get("domain"); d != "" {
					domain = d
				}
			}
		}

		if username != "" || password != "" {
			if domain == "" {
				domain = "FORTIGATE-VM64"
			}
			h.baseService.LogEvent("credential_attempt", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"username": username,
				"password": password,
				"domain":   domain,
				"summary":  fmt.Sprintf("Captured FortiGate login attempt: %s\\%s (password: %s)", domain, username, password),
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

	// Dynamic HTTP exploit & payload parser
	rawPayload := path
	if len(body) > 0 {
		rawPayload += " " + string(body)
	}
	for hName, hVal := range headers {
		if hName != "host" {
			rawPayload += " " + hVal
		}
	}

	decodedPayload, _ := url.QueryUnescape(rawPayload)
	lowerPayload := strings.ToLower(decodedPayload)
	lowerUA := strings.ToLower(userAgent)
	cleanPath := strings.Split(path, "?")[0]

	// Determine if this request carries an exploit payload, scanner probe, or POST payload
	isExploit := false

	// 1. Shell commands & RCE keywords
	rceKeywords := []string{
		"wget", "curl", "chmod", "cd ", "exec", "eval", "system", "passthru",
		"base64", "powershell", "pwsh", "python", "perl", "nc ", "ncat", "netcat",
		"/bin/sh", "busybox", "tftp", "ftp -s", "cmd.exe", "cmd=", "exec=", "run=",
		"command=", "touch ", "mkdir ", "rm -", "cat /", "id;", "whoami",
	}
	for _, kw := range rceKeywords {
		if strings.Contains(lowerPayload, kw) {
			isExploit = true
			break
		}
	}

	// 2. Path Traversal & LFI
	if !isExploit {
		lfiKeywords := []string{"../", "..%2f", "%2e%2e", "/etc/passwd", "/etc/shadow", "boot.ini", "system32", "fgt_lang"}
		for _, kw := range lfiKeywords {
			if strings.Contains(lowerPayload, kw) {
				isExploit = true
				break
			}
		}
	}

	// 3. Web Exploits, SQLi, SSTI, JNDI & Scanner Probes
	if !isExploit {
		exploitKeywords := []string{
			"select ", "union ", "insert ", "drop ", "information_schema", "<?php", "<%",
			"${", "#{", "{{", "jndi:", "report runner", "node.js", "cmdb/system/admin",
			".cgi", ".env", ".git", "setup", "luci", "tplink", "netgear", "dlink", "hikvision",
			"solr", "spring", "actuator", "log4j", "xmlrpc",
		}
		for _, kw := range exploitKeywords {
			if strings.Contains(lowerPayload, kw) || strings.Contains(lowerUA, kw) {
				isExploit = true
				break
			}
		}
	}

	// 4. Any POST/PUT body on non-login endpoints
	if !isExploit && len(body) > 0 && cleanPath != "/remote/logincheck" && cleanPath != "/logincheck" {
		isExploit = true
	}

	if isExploit {
		var payloadBytes []byte
		if len(body) > 0 {
			payloadBytes = body
		} else {
			payloadBytes = []byte(decodedPayload)
		}

		hasher := sha256.New()
		hasher.Write(payloadBytes)
		sha256Sum := hex.EncodeToString(hasher.Sum(nil))

		// Derive dynamic filename based on path and payload type
		dynamicFilename := deriveDynamicPayloadFilename(cleanPath, payloadBytes, lowerPayload)

		malwareType, scanDetails := services.AnalyzePayload(dynamicFilename, payloadBytes)

		// Extract download URL dynamically
		downloadURL := ""
		for _, scheme := range []string{"http://", "https://", "ftp://", "tftp://"} {
			if idx := strings.Index(lowerPayload, scheme); idx != -1 {
				endIdx := strings.IndexAny(lowerPayload[idx:], " ;'\">\n\r\t")
				if endIdx != -1 {
					downloadURL = decodedPayload[idx : idx+endIdx]
				} else {
					downloadURL = decodedPayload[idx:]
				}
				break
			}
		}

		h.baseService.LogEvent("captured_payload", map[string]interface{}{
			"src_ip":       srcIP,
			"src_port":     srcPort,
			"profile":      h.profile.Name,
			"filename":     dynamicFilename,
			"file_size":    len(payloadBytes),
			"sha256":       sha256Sum,
			"malware_type": malwareType,
			"details":      scanDetails,
			"download_url": downloadURL,
			"summary":      fmt.Sprintf("Captured HTTP payload '%s' (%d bytes) from %s", dynamicFilename, len(payloadBytes), srcIP),
		})
	}

	// Prepare FortiGate HTTP Response according to request path and method
	var responseBody bytes.Buffer
	cleanPath = strings.Split(path, "?")[0]

	if method == "POST" && (cleanPath == "/remote/logincheck" || cleanPath == "/logincheck" || cleanPath == "/login" || cleanPath == "/") {
		// FortiGate Login Submission Handler
		isJSONRequest := strings.Contains(headers["content-type"], "application/json") || strings.Contains(headers["accept"], "application/json")
		if isJSONRequest {
			jsonResp := `{"status":"failed","error":401,"message":"Authentication failed. Invalid username or password."}`
			responseBody.WriteString("HTTP/1.1 401 Unauthorized\r\n")
			responseBody.WriteString("Server: FortiGate\r\n")
			responseBody.WriteString("Content-Type: application/json; charset=utf-8\r\n")
			responseBody.WriteString("Set-Cookie: SVPNCOOKIE=; path=/; Secure; HttpOnly\r\n")
			responseBody.WriteString("Content-Length: " + strconv.Itoa(len(jsonResp)) + "\r\n")
			responseBody.WriteString("Connection: close\r\n\r\n")
			responseBody.WriteString(jsonResp)
		} else {
			responseBody.WriteString("HTTP/1.1 302 Found\r\n")
			responseBody.WriteString("Server: FortiGate\r\n")
			responseBody.WriteString("Location: /remote/login?error=1\r\n")
			responseBody.WriteString("Set-Cookie: SVPNCOOKIE=; path=/; Secure; HttpOnly\r\n")
			responseBody.WriteString("Content-Length: 0\r\n")
			responseBody.WriteString("Connection: close\r\n\r\n")
		}
	} else if strings.HasPrefix(cleanPath, "/api/v2/") {
		// FortiOS REST API Response (e.g. CVE-2022-40684 endpoint)
		apiResp := `{"status":"error","http_status":401,"error":-3,"vdom":"root","path":"system","name":"admin"}`
		responseBody.WriteString("HTTP/1.1 401 Unauthorized\r\n")
		responseBody.WriteString("Server: FortiGate\r\n")
		responseBody.WriteString("Content-Type: application/json; charset=utf-8\r\n")
		responseBody.WriteString("Content-Length: " + strconv.Itoa(len(apiResp)) + "\r\n")
		responseBody.WriteString("Connection: close\r\n\r\n")
		responseBody.WriteString(apiResp)
	} else if cleanPath == "/sslvpn/portal.css" || cleanPath == "/css/style.css" {
		// FortiGate SSL-VPN Stylesheet
		cssContent := "/* FortiGate SSL-VPN Portal Styles */ body { background-color: #12161b; color: #e1e4e8; font-family: sans-serif; }"
		responseBody.WriteString("HTTP/1.1 200 OK\r\n")
		responseBody.WriteString("Server: FortiGate\r\n")
		responseBody.WriteString("Content-Type: text/css; charset=utf-8\r\n")
		responseBody.WriteString("Content-Length: " + strconv.Itoa(len(cssContent)) + "\r\n")
		responseBody.WriteString("Connection: close\r\n\r\n")
		responseBody.WriteString(cssContent)
	} else if cleanPath == "/favicon.ico" {
		// Official Fortinet Red SVG Favicon
		favBytes := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1537 1101"><path fill-rule="evenodd" fill="#ee3124" d="M.2 408.6h434.5v285.8H.2zM554.9 2.3h426.8v285.8H554.9zm0 811h426.8v285.8H554.9zm545.4-404.7h436v285.8h-436zM434.7 2.3v287.3H.2v-32.4C17.2 127.4 88 25.4 178.9 2.3zm1.6 811v285.8H168.2C81.9 1071.3 15.7 972.4.3 848.8v-35.5zm1100-526.8h-436V.7h257.3c90.9 24.7 161.8 126.7 178.7 254.9zm-436 814.1V814.9h436v35.5c-16.9 123.6-83.2 220.9-167.9 250.2z"/></svg>`)
		responseBody.WriteString("HTTP/1.1 200 OK\r\n")
		responseBody.WriteString("Server: FortiGate\r\n")
		responseBody.WriteString("Content-Type: image/svg+xml\r\n")
		responseBody.WriteString("Content-Length: " + strconv.Itoa(len(favBytes)) + "\r\n")
		responseBody.WriteString("Connection: close\r\n\r\n")
		responseBody.Write(favBytes)
	} else {
		// FortiGate Login HTML Interface
		htmlContent := fortigateLoginHTML
		responseBody.WriteString("HTTP/1.1 200 OK\r\n")
		responseBody.WriteString("Server: FortiGate\r\n")
		responseBody.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		responseBody.WriteString("Set-Cookie: SVPNCOOKIE=; path=/; Secure; HttpOnly\r\n")
		responseBody.WriteString("X-Frame-Options: SAMEORIGIN\r\n")
		responseBody.WriteString("X-XSS-Protection: 1; mode=block\r\n")
		responseBody.WriteString("Content-Length: " + strconv.Itoa(len(htmlContent)) + "\r\n")
		responseBody.WriteString("Connection: close\r\n\r\n")
		responseBody.WriteString(htmlContent)
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(responseBody.Bytes())
	return err
}

func deriveDynamicPayloadFilename(cleanPath string, body []byte, lowerPayload string) string {
	cleanPath = strings.Trim(cleanPath, "/")

	// 1. Check binary magic headers
	if len(body) >= 4 && string(body[:4]) == "\x7fELF" {
		return "elf_executable.bin"
	}
	if len(body) >= 2 && string(body[:2]) == "MZ" {
		return "pe_windows_executable.exe"
	}

	// 2. Check content signatures (PHP, JSON, XML)
	if strings.Contains(lowerPayload, "<?php") || strings.HasSuffix(cleanPath, ".php") {
		return "php_webshell.php"
	}
	if len(body) > 0 && body[0] == '{' {
		return "http_json_payload.json"
	}
	if len(body) > 0 && (body[0] == '<' || strings.Contains(lowerPayload, "soap")) {
		return "http_xml_soap_payload.xml"
	}

	// 3. Derive filename dynamically from requested URL path slug
	if cleanPath != "" {
		slug := strings.ReplaceAll(cleanPath, "/", "_")
		slug = strings.ReplaceAll(slug, "-", "_")
		slug = strings.ReplaceAll(slug, ".", "_")
		if len(slug) > 30 {
			slug = slug[:30]
		}
		if strings.Contains(lowerPayload, "wget") || strings.Contains(lowerPayload, "curl") || strings.Contains(lowerPayload, "chmod") || strings.Contains(lowerPayload, "sh") {
			return slug + "_rce.sh"
		}
		return slug + "_payload.txt"
	}

	if strings.Contains(lowerPayload, "wget") || strings.Contains(lowerPayload, "curl") || strings.Contains(lowerPayload, "chmod") || strings.Contains(lowerPayload, "sh") {
		return "http_rce_payload.sh"
	}

	return "http_payload.txt"
}

func init() {
	services.Registry["http"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewHTTPHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *HTTPHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
