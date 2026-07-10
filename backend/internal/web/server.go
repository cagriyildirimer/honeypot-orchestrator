package web

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/config"
	"honeypot-orchestrator/backend/internal/database"
	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/siem"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	db            *database.DB
	config        *config.AppConfig
	logger        *logger.EventLogger
	defense       *defense.DefenseSystem
	orch          *services.Orchestrator
	csrfTokens    map[string]time.Time
	csrfMu        sync.RWMutex
	loginAttempts map[string][]time.Time
	loginMu       sync.Mutex
	alertStreamer   *AlertStreamer
	siemForwarder   *siem.Forwarder
	statsCache      map[string]interface{}
	statsLastUpdate time.Time
	statsMu         sync.Mutex
}

type contextKey string

const sessionContextKey contextKey = "session"

func NewServer(
	db *database.DB,
	cfg *config.AppConfig,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	orch *services.Orchestrator,
	sf *siem.Forwarder,
) *Server {
	return &Server{
		db:            db,
		config:        cfg,
		logger:        el,
		defense:       ds,
		orch:          orch,
		csrfTokens:    make(map[string]time.Time),
		loginAttempts: make(map[string][]time.Time),
		alertStreamer: NewAlertStreamer(db),
		siemForwarder: sf,
	}
}

func (s *Server) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.Header.Get("X-Csrf-Token")
		}

		if token == "" {
			JSONResponse(w, http.StatusForbidden, map[string]string{"error": "CSRF token missing"})
			return
		}

		s.csrfMu.Lock()
		created, exists := s.csrfTokens[token]
		if exists {
			delete(s.csrfTokens, token)
		}
		s.csrfMu.Unlock()

		if !exists || time.Since(created) > 24*time.Hour {
			JSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid or expired CSRF token"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			JSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
			return
		}

		session, err := s.db.GetSession(r.Context(), cookie.Value)
		if err != nil {
			JSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "Session invalid or expired"})
			return
		}

		ctx := context.WithValue(r.Context(), sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) StartServer(ctx context.Context) error {
	s.alertStreamer.Start(ctx)
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/healthz", s.HandleHealthz)
	r.Get("/api/csrf", s.HandleCSRF)
	r.Post("/api/login", s.HandleLogin)
	r.Post("/api/logout", s.HandleLogout)
	r.Post("/api/test/inject-event", s.HandleInjectEvent)

	r.Group(func(r chi.Router) {
		r.Use(s.SessionMiddleware)
		r.Use(s.CSRFMiddleware)

		r.Get("/api/session", s.HandleSession)
		r.Get("/api/status", s.HandleStatus)
		r.Get("/api/overview", s.HandleOverview)
		r.Get("/api/threat-intel", s.HandleThreatIntel)
		r.Get("/api/analyze", s.HandleAnalyze)
		r.Get("/api/events", s.HandleEvents)
		r.Get("/api/stats", s.HandleStats)
		r.Get("/api/alerts/stream", s.alertStreamer.ServeHTTP)

		// Profiles and Service controls
		r.Post("/api/profile", s.HandleProfile)
		r.Post("/api/services/toggle", s.HandleServicesToggle)

		// Whitelist controls
		r.Get("/api/whitelist", s.HandleGetWhitelist)
		r.Post("/api/whitelist", s.HandleAddWhitelist)
		r.Post("/api/whitelist/delete", s.HandleDeleteWhitelist)

		// Blacklist controls
		r.Get("/api/blacklist", s.HandleGetBlacklist)
		r.Post("/api/blacklist", s.HandleAddBlacklist)
		r.Post("/api/blacklist/delete", s.HandleDeleteBlacklist)

		// Whitelist/Blacklist Settings
		r.Get("/api/settings/auto-blacklist", s.HandleGetAutoBlacklist)
		r.Post("/api/settings/auto-blacklist", s.HandleSetAutoBlacklist)

		// SIEM Target Settings
		r.Get("/api/settings/siem", s.HandleGetSiem)
		r.Post("/api/settings/siem", s.HandleSetSiem)
		r.Post("/api/settings/siem/test", s.HandleTestSiem)

		// User Management
		r.Get("/api/users", s.HandleGetUsers)
		r.Post("/api/users", s.HandleCreateUser)
		r.Post("/api/users/delete", s.HandleDeleteUser)
		r.Post("/api/users/password", s.HandleChangePassword)
		r.Post("/api/users/role", s.HandleChangeRole)

		// Settings Overview Page
		r.Get("/api/settings", s.HandleGetSettings)
	})

	addr := fmt.Sprintf("%s:%d", s.config.Web.Host, s.config.Web.Port)
	srv := &http.Server{
		Addr:        addr,
		Handler:     r,
		ReadTimeout: 15 * time.Second,
		// Disable WriteTimeout (set to 0) to allow infinite streaming for Server-Sent Events (SSE)
		WriteTimeout: 0,
	}

	log.Printf("Go Web API Server listening on http://%s...\n", addr)

	// Periodic expired session cleanup
	go func() {
		if err := s.db.CleanupExpiredSessions(ctx); err != nil {
			log.Println("Error cleaning up expired sessions on startup:", err)
		}
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.db.CleanupExpiredSessions(ctx); err != nil {
					log.Println("Error cleaning up expired sessions:", err)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}
