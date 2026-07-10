package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/database"
	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/siem"
)

type ProfileRequest struct {
	Profile string `json:"profile"`
}

type ToggleRequest struct {
	Service string `json:"service"`
	Enabled bool   `json:"enabled"`
}

type WhitelistRequest struct {
	IP          string `json:"ip"`
	Description string `json:"description"`
}

type BlacklistRequest struct {
	IP          string `json:"ip"`
	Description string `json:"description"`
}

type AutoBlacklistRequest struct {
	Enabled bool `json:"enabled"`
}

type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
}

func (s *Server) HandleProfile(w http.ResponseWriter, r *http.Request) {
	var req ProfileRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if err := s.orch.SetProfile(r.Context(), req.Profile); err != nil {
		JSONResponse(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	s.HandleStatus(w, r)
}

func (s *Server) HandleServicesToggle(w http.ResponseWriter, r *http.Request) {
	var req ToggleRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	success := s.orch.ToggleService(r.Context(), req.Service, req.Enabled)
	JSONResponse(w, http.StatusOK, map[string]bool{"ok": success})
}

func (s *Server) HandleGetWhitelist(w http.ResponseWriter, r *http.Request) {
	list, err := s.defense.GetWhitelist(r.Context())
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if list == nil {
		list = []defense.WhitelistEntry{}
	}
	JSONResponse(w, http.StatusOK, map[string]interface{}{"whitelist": list})
}

func (s *Server) HandleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req WhitelistRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.IP == "" || req.Description == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "IP and description are required."})
		return
	}

	if err := s.defense.AddToWhitelist(r.Context(), req.IP, req.Description); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.HandleGetWhitelist(w, r)
}

func (s *Server) HandleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	var req WhitelistRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.IP == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "IP is required."})
		return
	}

	found, err := s.defense.DeleteFromWhitelist(r.Context(), req.IP)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		JSONResponse(w, http.StatusNotFound, map[string]string{"error": "Not found in whitelist."})
		return
	}

	s.HandleGetWhitelist(w, r)
}

func (s *Server) HandleGetBlacklist(w http.ResponseWriter, r *http.Request) {
	list, err := s.defense.GetBlacklist(r.Context())
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if list == nil {
		list = []defense.BlacklistEntry{}
	}
	JSONResponse(w, http.StatusOK, map[string]interface{}{"blacklist": list})
}

func (s *Server) HandleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	var req BlacklistRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.IP == "" || req.Description == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "IP/MAC and description are required."})
		return
	}

	if err := s.defense.AddToBlacklist(r.Context(), req.IP, req.Description); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.HandleGetBlacklist(w, r)
}

func (s *Server) HandleDeleteBlacklist(w http.ResponseWriter, r *http.Request) {
	var req BlacklistRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.IP == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "IP/MAC is required."})
		return
	}

	found, err := s.defense.DeleteFromBlacklist(r.Context(), req.IP)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		JSONResponse(w, http.StatusNotFound, map[string]string{"error": "Not found in blacklist."})
		return
	}

	s.HandleGetBlacklist(w, r)
}

func (s *Server) HandleGetAutoBlacklist(w http.ResponseWriter, r *http.Request) {
	enabled := s.defense.IsAutoBlacklistEnabled(r.Context())
	JSONResponse(w, http.StatusOK, map[string]bool{"auto_blacklist_enabled": enabled})
}

func (s *Server) HandleSetAutoBlacklist(w http.ResponseWriter, r *http.Request) {
	var req AutoBlacklistRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	val := "false"
	if req.Enabled {
		val = "true"
	}

	if err := s.db.SaveSystemSetting(r.Context(), "auto_blacklist_enabled", val); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{"ok": true, "auto_blacklist_enabled": req.Enabled})
}

type SiemRequest struct {
	Configs []siem.SiemTarget `json:"configs"`
}

func (s *Server) HandleGetSiem(w http.ResponseWriter, r *http.Request) {
	val, err := s.db.GetSystemSetting(r.Context(), "siem_config")
	if err != nil || val == "" {
		JSONResponse(w, http.StatusOK, map[string]interface{}{"configs": []interface{}{}})
		return
	}

	var req SiemRequest
	if err := json.Unmarshal([]byte(val), &req); err != nil {
		JSONResponse(w, http.StatusOK, map[string]interface{}{"configs": []interface{}{}})
		return
	}

	if req.Configs == nil {
		req.Configs = []siem.SiemTarget{}
	}
	JSONResponse(w, http.StatusOK, map[string]interface{}{"configs": req.Configs})
}

func (s *Server) HandleSetSiem(w http.ResponseWriter, r *http.Request) {
	var req SiemRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	// Assign unique IDs to new configurations if they don't have one
	for i, config := range req.Configs {
		if config.ID == "" {
			req.Configs[i].ID = fmt.Sprintf("siem-%d", time.Now().UnixNano()+int64(i))
		}
	}

	valBytes, err := json.Marshal(req)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if err := s.db.SaveSystemSetting(r.Context(), "siem_config", string(valBytes)); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Dynamic update of runtime configurations in forwarder
	_ = s.siemForwarder.LoadConfig(string(valBytes))

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"message": "SIEM configuration updated.",
		"configs": req.Configs,
	})
}

func (s *Server) HandleTestSiem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	val, err := s.db.GetSystemSetting(r.Context(), "siem_config")
	if err != nil || val == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "SIEM is not configured."})
		return
	}

	var storedConfigs SiemRequest
	if err := json.Unmarshal([]byte(val), &storedConfigs); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Invalid SIEM configuration format"})
		return
	}

	var target *siem.SiemTarget
	if req.ID != "" {
		for i := range storedConfigs.Configs {
			if storedConfigs.Configs[i].ID == req.ID {
				target = &storedConfigs.Configs[i]
				break
			}
		}
	} else {
		var enabled []siem.SiemTarget
		for i := range storedConfigs.Configs {
			if storedConfigs.Configs[i].Enabled {
				enabled = append(enabled, storedConfigs.Configs[i])
			}
		}
		if len(enabled) == 1 {
			target = &enabled[0]
		}
	}

	if target == nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Select an enabled SIEM target to test."})
		return
	}

	testEvent := &database.Event{
		Timestamp: time.Now().UTC(),
		Service:   "system",
		EventType: "siem_test",
		Summary:   func() *string { s := "Honeypot Director SIEM connection test."; return &s }(),
	}

	err = s.siemForwarder.ForwardTo(*target, testEvent)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"message": "Test event sent to SIEM.",
	})
}

func (s *Server) HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.GetAllUsers(r.Context())
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if users == nil {
		users = []*database.User{}
	}
	JSONResponse(w, http.StatusOK, map[string]interface{}{"users": users})
}

func (s *Server) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req UserRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.Username == "" || req.Password == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Username and password are required."})
		return
	}

	// Verify if user already exists
	if _, err := s.db.GetUser(r.Context(), req.Username); err == nil {
		JSONResponse(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("User already exists: %s.", req.Username)})
		return
	}

	hashed, err := HashPassword(req.Password)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	role := req.Role
	if role == "" {
		role = "viewer"
	}

	if err := s.db.SaveUser(r.Context(), req.Username, hashed, role); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logger.Log(map[string]interface{}{
		"service":    "web",
		"event_type": "user_created",
		"summary":    fmt.Sprintf("Dashboard user %s was created.", req.Username),
	})

	s.HandleGetUsers(w, r)
}

func (s *Server) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	var req UserRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.Username == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Username is required."})
		return
	}

	// Verify current session username from context
	session, ok := r.Context().Value(sessionContextKey).(*database.Session)
	if ok && session.Username == req.Username {
		JSONResponse(w, http.StatusConflict, map[string]string{"error": "You cannot delete the signed-in user."})
		return
	}

	// Get all remaining users to count admins
	users, err := s.db.GetAllUsers(r.Context())
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if len(users) <= 1 {
		JSONResponse(w, http.StatusConflict, map[string]string{"error": "At least one user must remain."})
		return
	}

	adminCount := 0
	targetIsAdmin := false
	for _, u := range users {
		if u.Role == "admin" {
			adminCount++
		}
		if u.Username == req.Username && u.Role == "admin" {
			targetIsAdmin = true
		}
	}

	if targetIsAdmin && adminCount <= 1 {
		JSONResponse(w, http.StatusConflict, map[string]string{"error": "At least one admin user must remain."})
		return
	}

	if err := s.db.DeleteUser(r.Context(), req.Username); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logger.Log(map[string]interface{}{
		"service":    "web",
		"event_type": "user_deleted",
		"summary":    fmt.Sprintf("Dashboard user %s was deleted.", req.Username),
	})

	s.HandleGetUsers(w, r)
}

func (s *Server) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req UserRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.Username == "" || req.Password == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Username and new password are required."})
		return
	}

	hashed, err := HashPassword(req.Password)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	dbUser, err := s.db.GetUser(r.Context(), req.Username)
	if err != nil {
		JSONResponse(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("Unknown user: %s.", req.Username)})
		return
	}

	if err := s.db.SaveUser(r.Context(), req.Username, hashed, dbUser.Role); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logger.Log(map[string]interface{}{
		"service":    "web",
		"event_type": "user_password_changed",
		"summary":    fmt.Sprintf("Dashboard user %s password was changed.", req.Username),
	})

	s.HandleGetUsers(w, r)
}

func (s *Server) HandleChangeRole(w http.ResponseWriter, r *http.Request) {
	var req UserRequest
	if err := DecodeJSON(r, &req); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	if req.Username == "" || req.Role == "" {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Username and role are required."})
		return
	}

	dbUser, err := s.db.GetUser(r.Context(), req.Username)
	if err != nil {
		JSONResponse(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("Unknown user: %s.", req.Username)})
		return
	}

	// Prevent removing own admin privileges
	session, ok := r.Context().Value(sessionContextKey).(*database.Session)
	if ok && session.Username == req.Username && req.Role != "admin" {
		JSONResponse(w, http.StatusConflict, map[string]string{"error": "You cannot remove admin access from the signed-in user."})
		return
	}

	if err := s.db.SaveUser(r.Context(), req.Username, dbUser.PasswordHash, req.Role); err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logger.Log(map[string]interface{}{
		"service":    "web",
		"event_type": "user_role_changed",
		"summary":    fmt.Sprintf("Dashboard user %s role was changed to %s.", req.Username, req.Role),
	})

	s.HandleGetUsers(w, r)
}

func (s *Server) HandleGetSettings(w http.ResponseWriter, r *http.Request) {
	displayHost := getDisplayHost(r)
	logPath := s.config.Logging.Path
	logSize := int64(0)
	exists := false
	if info, err := os.Stat(logPath); err == nil {
		logSize = info.Size()
		exists = true
	}

	session, _ := r.Context().Value(sessionContextKey).(*database.Session)
	username := ""
	role := ""
	if session != nil {
		username = session.Username
		role = session.Role
	}

	// Memory calculations (mocked with realistic fallback data)
	totalRam := 8192.0
	usedRam := 2048.0
	ramPercent := 25.0

	// Check Linux /proc/meminfo for memory calculations
	if memFile, err := os.Open("/proc/meminfo"); err == nil {
		defer memFile.Close()
		var memTotal, memAvailable int64
		var junk string
		for {
			var label string
			var val int64
			n, _ := fmt.Fscanf(memFile, "%s %d %s\n", &label, &val, &junk)
			if n <= 0 {
				break
			}
			if label == "MemTotal:" {
				memTotal = val
			} else if label == "MemAvailable:" {
				memAvailable = val
			}
		}
		if memTotal > 0 {
			totalRam = float64(memTotal) / 1024.0
			usedRam = (float64(memTotal) - float64(memAvailable)) / 1024.0
			ramPercent = (usedRam / totalRam) * 100.0
		}
	}

	// CPU calculations (mocked with loadavg on Linux)
	cpuPercent := 1.5
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			if val, err := strconv.ParseFloat(parts[0], 64); err == nil {
				cpuPercent = val * 100.0 / float64(runtime.NumCPU())
				if cpuPercent > 100.0 {
					cpuPercent = 100.0
				}
			}
		}
	}

	// Disk calculations (df on Linux)
	totalDisk := 100.0
	usedDisk := 15.2
	diskPercent := 15.2

	if runtime.GOOS != "windows" {
		if out, err := exec.Command("df", "-k", "/").Output(); err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 1 {
				fields := strings.Fields(lines[1])
				if len(fields) >= 4 {
					totalKB, _ := strconv.ParseFloat(fields[1], 64)
					usedKB, _ := strconv.ParseFloat(fields[2], 64)
					if totalKB > 0 {
						totalDisk = totalKB / (1024 * 1024) // GB
						usedDisk = usedKB / (1024 * 1024)   // GB
						diskPercent = (usedDisk / totalDisk) * 100.0
					}
				}
			}
		}
	}

	// Uptime calculation
	uptimeSeconds := int(s.orch.Uptime().Seconds())
	uptimeStr := fmt.Sprintf("%dh %dm %ds", uptimeSeconds/3600, (uptimeSeconds%3600)/60, uptimeSeconds%60)

	// Fetch users list
	users, _ := s.db.GetAllUsers(r.Context())
	if users == nil {
		users = []*database.User{}
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"panel": map[string]interface{}{
			"url":          fmt.Sprintf("http://%s:%d", displayHost, s.config.Web.Port),
			"host":         s.config.Web.Host,
			"display_host": displayHost,
			"port":         s.config.Web.Port,
		},
		"session": map[string]string{
			"username": username,
			"role":     role,
		},
		"logging": map[string]interface{}{
			"path":       logPath,
			"size_bytes": logSize,
			"exists":     exists,
		},
		"runtime": map[string]interface{}{
			"uptime_seconds": uptimeSeconds,
			"uptime":         uptimeStr,
			"health":         "ok",
			"version":        "1.0.0",
		},
		"resources": map[string]interface{}{
			"cpu": map[string]interface{}{
				"percent": mathRound(cpuPercent, 1),
			},
			"ram": map[string]interface{}{
				"total_mb": mathRound(totalRam, 1),
				"used_mb":  mathRound(usedRam, 1),
				"percent":  mathRound(ramPercent, 1),
			},
			"disk": map[string]interface{}{
				"total_gb": mathRound(totalDisk, 1),
				"used_gb":  mathRound(usedDisk, 1),
				"percent":  mathRound(diskPercent, 1),
			},
		},
		"users": users,
	})
}

func mathRound(val float64, precision int) float64 {
	format := "%." + strconv.Itoa(precision) + "f"
	resStr := fmt.Sprintf(format, val)
	res, _ := strconv.ParseFloat(resStr, 64)
	return res
}

func (s *Server) HandleInjectEvent(w http.ResponseWriter, r *http.Request) {
	var evt map[string]interface{}
	if err := DecodeJSON(r, &evt); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	// Direct injection through the EventLogger so it pops up in the SSE live alerts stream
	s.logger.Log(evt)

	JSONResponse(w, http.StatusOK, map[string]string{
		"status":  "event_injected",
		"message": "Event successfully logged, saved to DB, and broadcasted to Web UI",
	})
}
