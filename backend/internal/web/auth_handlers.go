package web

import (
	"net"
	"net/http"
	"time"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Ok       bool   `json:"ok"`
	Username string `json:"username,omitempty"`
	Role     string `json:"role,omitempty"`
	Error    string `json:"error,omitempty"`
}

type SessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username"`
	Role          string `json:"role"`
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	now := time.Now()

	s.loginMu.Lock()
	attempts := s.loginAttempts[clientIP]
	var activeAttempts []time.Time
	for _, t := range attempts {
		if now.Sub(t) < 5*time.Minute {
			activeAttempts = append(activeAttempts, t)
		}
	}
	s.loginAttempts[clientIP] = activeAttempts

	if len(activeAttempts) >= 5 {
		s.loginMu.Unlock()
		JSONResponse(w, http.StatusTooManyRequests, LoginResponse{
			Ok:    false,
			Error: "Too many failed attempts. Try again in 5 minutes.",
		})
		return
	}
	s.loginMu.Unlock()

	var req LoginRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, LoginResponse{Ok: false, Error: "Invalid request payload"})
		return
	}

	dbUser, err := s.db.GetUser(r.Context(), req.Username)
	if err != nil || !VerifyPassword(req.Password, dbUser.PasswordHash) {
		s.loginMu.Lock()
		s.loginAttempts[clientIP] = append(s.loginAttempts[clientIP], now)
		s.loginMu.Unlock()

		s.logger.Log(map[string]interface{}{
			"service":    "web",
			"event_type": "login_failed",
			"src_ip":     clientIP,
			"summary":    "Dashboard login failed for " + req.Username + ".",
		})

		JSONResponse(w, http.StatusUnauthorized, LoginResponse{
			Ok:    false,
			Error: "Invalid username or password.",
		})
		return
	}

	s.loginMu.Lock()
	delete(s.loginAttempts, clientIP)
	s.loginMu.Unlock()

	sessionToken := generateToken(32)
	if err := s.db.SaveSession(r.Context(), sessionToken, req.Username, dbUser.Role); err != nil {
		JSONResponse(w, http.StatusInternalServerError, LoginResponse{Ok: false, Error: "Session storage failed"})
		return
	}

	s.logger.Log(map[string]interface{}{
		"service":    "web",
		"event_type": "login_success",
		"src_ip":     clientIP,
		"summary":    "Dashboard login success for " + req.Username + ".",
	})

	isSecure := r.Header.Get("X-Forwarded-Proto") == "https"
	cookie := &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	JSONResponse(w, http.StatusOK, LoginResponse{
		Ok:       true,
		Username: req.Username,
		Role:     dbUser.Role,
	})
}

func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		_ = s.db.DeleteSession(r.Context(), cookie.Value)
	}

	isSecure := r.Header.Get("X-Forwarded-Proto") == "https"
	expiredCookie := &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, expiredCookie)

	JSONResponse(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) HandleSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		JSONResponse(w, http.StatusOK, SessionResponse{Authenticated: false})
		return
	}

	session, err := s.db.GetSession(r.Context(), cookie.Value)
	if err != nil {
		JSONResponse(w, http.StatusOK, SessionResponse{Authenticated: false})
		return
	}

	JSONResponse(w, http.StatusOK, SessionResponse{
		Authenticated: true,
		Username:      session.Username,
		Role:          session.Role,
	})
}
