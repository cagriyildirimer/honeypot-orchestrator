package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
)

var Registry = make(map[string]func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) HoneypotService)

type HoneypotService interface {
	Name() string
	Port() int
	Proto() string
	Start(ctx context.Context) error
	Stop() error
	IsRunning() bool
	PortNameHost() string
}

type BaseTCPService struct {
	name              string
	host              string
	port              int
	logger            *logger.EventLogger
	defense           *defense.DefenseSystem
	listener          net.Listener
	wg                sync.WaitGroup
	ctx               context.Context
	cancel            context.CancelFunc
	isRunning         bool
	mu                sync.RWMutex
	tlsConfig         *tls.Config
	connectionHandler func(ctx context.Context, conn net.Conn) error
}

func NewBaseTCPService(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	handler func(ctx context.Context, conn net.Conn) error,
) *BaseTCPService {
	return &BaseTCPService{
		name:              name,
		host:              host,
		port:              port,
		logger:            el,
		defense:           ds,
		connectionHandler: handler,
	}
}

func (s *BaseTCPService) Name() string {
	return s.name
}

func (s *BaseTCPService) Port() int {
	return s.port
}

func (s *BaseTCPService) Proto() string {
	return "tcp"
}

func (s *BaseTCPService) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRunning
}

func (s *BaseTCPService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	var err error
	var l net.Listener

	if s.tlsConfig != nil {
		l, err = tls.Listen("tcp", addr, s.tlsConfig)
	} else {
		l, err = net.Listen("tcp", addr)
	}

	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = l
	s.isRunning = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.LogEvent("service_started", map[string]interface{}{
		"summary": fmt.Sprintf("%s listening.", s.name),
	})

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *BaseTCPService) Stop() error {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return nil
	}
	s.isRunning = false
	s.cancel()
	s.listener.Close()
	s.mu.Unlock()

	s.wg.Wait()

	s.LogEvent("service_stopped", map[string]interface{}{
		"summary": fmt.Sprintf("%s stopped.", s.name),
	})

	return nil
}

func (s *BaseTCPService) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("[%s] Accept error: %v\n", s.name, err)
				continue
			}
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConnection(c)
		}(conn)
	}
}

func (s *BaseTCPService) handleConnection(conn net.Conn) {
	// Note: We do not defer conn.Close() here directly anymore, as tarpitConnection manages its own lifecycle.
	// We only close it in the normal path or error branches.

	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		conn.Close()
		return
	}
	peerIP := tcpAddr.IP.String()
	peerPort := tcpAddr.Port

	dbCtx, dbCancel := context.WithTimeout(context.Background(), 3*time.Second)
	blacklisted, err := s.defense.IsBlacklisted(dbCtx, peerIP)
	dbCancel()
	if err != nil {
		log.Printf("[%s] Error checking blacklist for %s: %v\n", s.name, peerIP, err)
	}
	if blacklisted {
		s.tarpitConnection(conn, peerIP, peerPort)
		return
	}

	defer conn.Close()

	dbCtx2, dbCancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	s.defense.RecordSuspiciousEvent(dbCtx2, peerIP)
	dbCancel2()

	// Note: Individual service handlers manage their own read/write deadlines
	// since interactive protocols like SSH and SMB need longer sessions.
	if err := s.connectionHandler(s.ctx, conn); err != nil {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.LogEvent("connection_error", map[string]interface{}{
				"src_ip":   peerIP,
				"src_port": peerPort,
				"error":    err.Error(),
			})
		}
	}
}

func (s *BaseTCPService) tarpitConnection(conn net.Conn, peerIP string, peerPort int) {
	defer conn.Close()

	s.LogEvent("tarpit_hooked", map[string]interface{}{
		"src_ip":   peerIP,
		"src_port": peerPort,
		"summary":  fmt.Sprintf("Blacklisted attacker %s trapped in TCP Tarpit.", peerIP),
	})

	buffer := make([]byte, 128)
	for {
		// Set a long read deadline
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, err := conn.Read(buffer)
		if err != nil {
			// If client connection is still open but timeout, send dummy bytes to keep it alive
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, err = conn.Write([]byte("\r\n"))
				if err != nil {
					break
				}
				continue
			}
			break
		}
		// Slow down response to a crawl to trap their socket threads
		time.Sleep(15 * time.Second)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("\r\n"))
		if err != nil {
			break
		}
	}

	s.LogEvent("tarpit_released", map[string]interface{}{
		"src_ip":   peerIP,
		"src_port": peerPort,
		"summary":  fmt.Sprintf("Attacker %s connection closed, released from Tarpit.", peerIP),
	})
}

func (s *BaseTCPService) LogEvent(eventType string, fields map[string]interface{}) {
	payload := map[string]interface{}{
		"service":    s.name,
		"event_type": eventType,
	}
	for k, v := range fields {
		payload[k] = v
	}
	s.logger.Log(payload)
}

type BaseUDPService struct {
	name            string
	host            string
	port            int
	logger          *logger.EventLogger
	defense         *defense.DefenseSystem
	conn            *net.UDPConn
	wg              sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	isRunning       bool
	mu              sync.RWMutex
	datagramHandler func(ctx context.Context, data []byte, srcAddr *net.UDPAddr) ([]byte, error)
}

func NewBaseUDPService(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	handler func(ctx context.Context, data []byte, srcAddr *net.UDPAddr) ([]byte, error),
) *BaseUDPService {
	return &BaseUDPService{
		name:            name,
		host:            host,
		port:            port,
		logger:          el,
		defense:         ds,
		datagramHandler: handler,
	}
}

func (s *BaseUDPService) Name() string {
	return s.name
}

func (s *BaseUDPService) Port() int {
	return s.port
}

func (s *BaseUDPService) Proto() string {
	return "udp"
}

func (s *BaseUDPService) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRunning
}

func (s *BaseUDPService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return nil
	}

	addrStr := fmt.Sprintf("%s:%d", s.host, s.port)
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		s.mu.Unlock()
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on UDP %s: %w", addrStr, err)
	}

	s.conn = conn
	s.isRunning = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.LogEvent("service_started", map[string]interface{}{
		"summary": fmt.Sprintf("%s listening (UDP).", s.name),
	})

	s.wg.Add(1)
	go s.readLoop()

	return nil
}

func (s *BaseUDPService) Stop() error {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return nil
	}
	s.isRunning = false
	s.cancel()
	s.conn.Close()
	s.mu.Unlock()

	s.wg.Wait()

	s.LogEvent("service_stopped", map[string]interface{}{
		"summary": fmt.Sprintf("%s stopped.", s.name),
	})

	return nil
}

func (s *BaseUDPService) readLoop() {
	defer s.wg.Done()

	buf := make([]byte, 4096)
	for {
		n, srcAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("[%s] ReadFromUDP error: %v\n", s.name, err)
				return
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		s.wg.Add(1)
		go func(d []byte, addr *net.UDPAddr) {
			defer s.wg.Done()
			s.handleDatagram(d, addr)
		}(data, srcAddr)
	}
}

func (s *BaseUDPService) handleDatagram(data []byte, srcAddr *net.UDPAddr) {
	peerIP := srcAddr.IP.String()

	dbCtx, dbCancel := context.WithTimeout(context.Background(), 3*time.Second)
	blacklisted, err := s.defense.IsBlacklisted(dbCtx, peerIP)
	dbCancel()
	if err != nil {
		log.Printf("[%s] Error checking blacklist for %s: %v\n", s.name, peerIP, err)
	}
	if blacklisted {
		return
	}

	dbCtx2, dbCancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	s.defense.RecordSuspiciousEvent(dbCtx2, peerIP)
	dbCancel2()

	resp, err := s.datagramHandler(s.ctx, data, srcAddr)
	if err != nil {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.LogEvent("connection_error", map[string]interface{}{
				"src_ip":   peerIP,
				"src_port": srcAddr.Port,
				"error":    err.Error(),
			})
		}
		return
	}

	if len(resp) > 0 {
		s.conn.WriteToUDP(resp, srcAddr)
	}
}

func (s *BaseUDPService) LogEvent(eventType string, fields map[string]interface{}) {
	payload := map[string]interface{}{
		"service":    s.name,
		"event_type": eventType,
	}
	for k, v := range fields {
		payload[k] = v
	}
	s.logger.Log(payload)
}
