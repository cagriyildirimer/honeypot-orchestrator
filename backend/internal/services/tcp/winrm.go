package tcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
	"honeypot-orchestrator/backend/internal/services"
)

type WinRMHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
}

func NewWinRMHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *WinRMHoneypot {
	w := &WinRMHoneypot{
		profile: initialProfile,
	}
	w.baseService = services.NewBaseTCPService(name, host, port, el, ds, w.handleClient)
	return w
}

func (w *WinRMHoneypot) Name() string {
	return w.baseService.Name()
}

func (w *WinRMHoneypot) Port() int {
	return w.baseService.Port()
}

func (w *WinRMHoneypot) Proto() string {
	return w.baseService.Proto()
}

func (w *WinRMHoneypot) IsRunning() bool {
	return w.baseService.IsRunning()
}

func (w *WinRMHoneypot) Start(ctx context.Context) error {
	return w.baseService.Start(ctx)
}

func (w *WinRMHoneypot) Stop() error {
	return w.baseService.Stop()
}

func (w *WinRMHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	w.profile = prof
}

func (w *WinRMHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	w.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	reader := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}

		w.baseService.LogEvent("winrm_request", map[string]interface{}{
			"src_ip":     srcIP,
			"src_port":    srcPort,
			"method":     req.Method,
			"uri":        req.URL.RequestURI(),
			"user_agent":  req.UserAgent(),
			"summary":    fmt.Sprintf("WinRM HTTP %s request to %s", req.Method, req.URL.Path),
		})

		var responseBody string
		var statusCode int
		var contentType string

		// Check if it's a POST request to wsman endpoint
		if req.Method == "POST" && (strings.HasPrefix(req.URL.Path, "/wsman") || strings.HasPrefix(req.URL.Path, "/wsman/")) {
			bodyBytes, _ := io.ReadAll(io.LimitReader(req.Body, 4096))
			req.Body.Close()

			bodyStr := string(bodyBytes)
			if strings.Contains(bodyStr, "Identify") {
				statusCode = 200
				contentType = "application/soap+xml;charset=UTF-8"
				responseBody = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
        <a:Action>http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd/IdentifyResponse</a:Action>
    </s:Header>
    <s:Body>
        <wsmid:IdentifyResponse xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
            <wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>
            <wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>
            <wsmid:ProductVersion>OS: 10.0.17763 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>
        </wsmid:IdentifyResponse>
    </s:Body>
</s:Envelope>`
			} else {
				statusCode = 400
				contentType = "application/soap+xml;charset=UTF-8"
				responseBody = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault">
    <s:Header>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    </s:Header>
    <s:Body>
        <s:Fault>
            <s:Code><s:Value>s:Sender</s:Value></s:Code>
            <s:Reason><s:Text xml:lang="en-US">The request could not be processed.</s:Text></s:Reason>
            <s:Detail>
                <f:WSManFault Code="2150858495" Machine="WIN-SRV2019"><f:Message>The WS-Management service cannot process the request.</f:Message></f:WSManFault>
            </s:Detail>
        </s:Fault>
    </s:Body>
</s:Envelope>`
			}
		} else {
			statusCode = 404
			contentType = "text/html"
			responseBody = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\"http://www.w3.org/TR/html4/strict.dtd\">\r\n<HTML><HEAD><TITLE>Not Found</TITLE>\r\n<META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=us-ascii\"></HEAD>\r\n<BODY><h2>Not Found</h2>\r\n<hr><p>HTTP Error 404. The requested resource is not found.</p>\r\n</BODY></HTML>"
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		respStr := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
			"Content-Type: %s\r\n"+
			"Server: Microsoft-HTTPAPI/2.0\r\n"+
			"Date: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n"+
			"%s",
			statusCode, http.StatusText(statusCode),
			contentType,
			time.Now().UTC().Format(time.RFC1123),
			len(responseBody),
			responseBody,
		)

		_, err = conn.Write([]byte(respStr))
		if err != nil {
			return err
		}
		break
	}
	return nil
}

func init() {
	services.Registry["winrm"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewWinRMHoneypot(name, host, port, el, ds, prof)
	}
}

func (w *WinRMHoneypot) PortNameHost() string {
	return w.baseService.PortNameHost()
}
