package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/config"
	"honeypot-orchestrator/backend/internal/database"
	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
	"honeypot-orchestrator/backend/internal/system"
)

type Orchestrator struct {
	db            *database.DB
	config        *config.AppConfig
	logger        *logger.EventLogger
	defense       *defense.DefenseSystem
	services      map[string]HoneypotService
	mangler       system.PacketMangler
	activeProfile string
	overrides     map[string]bool
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	startedAt     time.Time
}

type DBState struct {
	ActiveProfile    string          `json:"active_profile"`
	ServiceOverrides map[string]bool `json:"service_overrides"`
	RunningServices  []string        `json:"running_services"`
}

func NewOrchestrator(
	db *database.DB,
	cfg *config.AppConfig,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *Orchestrator {
	o := &Orchestrator{
		db:            db,
		config:        cfg,
		logger:        el,
		defense:       ds,
		services:      make(map[string]HoneypotService),
		mangler:       system.NewPacketMangler(1),
		activeProfile: cfg.Profile,
		overrides:     make(map[string]bool),
		startedAt:     time.Now(),
	}

	// Initialize all possible services (in stopped state)
	prof := profiles.GetProfile(o.activeProfile)

	for name, c := range cfg.Services {
		tmpl := name
		for _, prefix := range []string{"http_", "telnet_", "ssh_", "ftp_", "rdp_", "dns_", "ldaps_", "llmnr_", "nbtnns_", "netbios_", "rpc_", "ldap_", "mssql_", "smb_"} {
			if strings.HasPrefix(name, prefix) {
				tmpl = prefix[:len(prefix)-1]
				break
			}
		}

		if factory, ok := Registry[tmpl]; ok {
			o.services[name] = factory(name, c.Host, c.Port, el, ds, prof)
		} else {
			log.Printf("Unknown service template type for service: %s", name)
		}
	}

	return o
}

func (o *Orchestrator) Start(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.ctx, o.cancel = context.WithCancel(ctx)

	if os.Getenv("HONEYPOT_DECOYS_ENABLED") == "false" {
		log.Println("[ORCHESTRATOR] Running in Web-only mode. Decoy services disabled.")
		return nil
	}

	o.mangler.Start()

	// Initial load state from DB or set default config state
	initialState, err := o.getDBState(o.ctx)
	if err != nil {
		initialState = DBState{
			ActiveProfile:    "empty",
			ServiceOverrides: make(map[string]bool),
			RunningServices:  []string{},
		}
		// Write initial state to DB
		stateBytes, _ := json.Marshal(initialState)
		o.db.SaveSystemSetting(o.ctx, "orchestrator_state", string(stateBytes))
	}

	o.activeProfile = initialState.ActiveProfile
	o.overrides = initialState.ServiceOverrides

	// Apply initial profile configuration
	o.applyState(o.ctx, initialState.ActiveProfile, initialState.ServiceOverrides)

	o.wg.Add(1)
	go o.syncLoop()

	return nil
}

func (o *Orchestrator) Stop() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.cancel != nil {
		o.cancel()
	}
	o.wg.Wait()

	if os.Getenv("HONEYPOT_DECOYS_ENABLED") == "false" {
		return nil
	}

	o.mangler.Stop()
	system.CleanupFirewall()

	// Stop all running services
	for _, svc := range o.services {
		if svc.IsRunning() {
			svc.Stop()
		}
	}

	return nil
}

func (o *Orchestrator) Uptime() time.Duration {
	return time.Since(o.startedAt)
}

func (o *Orchestrator) SetProfile(ctx context.Context, name string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	prof := profiles.GetProfile(name)
	if prof == nil {
		return fmt.Errorf("unknown profile: %s", name)
	}

	state, err := o.getDBState(ctx)
	if err != nil {
		state = DBState{}
	}

	state.ActiveProfile = name
	state.ServiceOverrides = make(map[string]bool) // Clear overrides on profile change

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return err
	}

	if err := o.db.SaveSystemSetting(ctx, "orchestrator_state", string(stateBytes)); err != nil {
		return err
	}

	// Hot reload state
	o.activeProfile = name
	o.overrides = state.ServiceOverrides
	if os.Getenv("HONEYPOT_DECOYS_ENABLED") != "false" {
		o.applyState(ctx, name, state.ServiceOverrides)
	}

	return nil
}

func (o *Orchestrator) ToggleService(ctx context.Context, name string, enabled bool) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, ok := o.services[name]; !ok {
		return false
	}

	state, err := o.getDBState(ctx)
	if err != nil {
		state = DBState{
			ActiveProfile:    o.activeProfile,
			ServiceOverrides: make(map[string]bool),
		}
	}

	if state.ServiceOverrides == nil {
		state.ServiceOverrides = make(map[string]bool)
	}
	state.ServiceOverrides[name] = enabled

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return false
	}

	if err := o.db.SaveSystemSetting(ctx, "orchestrator_state", string(stateBytes)); err != nil {
		return false
	}

	// Hot reload state
	o.overrides = state.ServiceOverrides
	if os.Getenv("HONEYPOT_DECOYS_ENABLED") != "false" {
		o.applyState(ctx, o.activeProfile, state.ServiceOverrides)
	}

	return true
}

func (o *Orchestrator) getDBState(ctx context.Context) (DBState, error) {
	val, err := o.db.GetSystemSetting(ctx, "orchestrator_state")
	if err != nil {
		return DBState{}, err
	}

	var state DBState
	if err := json.Unmarshal([]byte(val), &state); err != nil {
		return DBState{}, err
	}

	if state.ServiceOverrides == nil {
		state.ServiceOverrides = make(map[string]bool)
	}
	if state.RunningServices == nil {
		state.RunningServices = []string{}
	}

	return state, nil
}

func (o *Orchestrator) applyState(ctx context.Context, profileName string, overrides map[string]bool) {
	prof := profiles.GetProfile(profileName)
	if prof == nil {
		prof = profiles.GetProfile("empty")
	}

	// Determine targeted services
	targetServices := make(map[string]bool)
	for _, name := range prof.Services {
		targetServices[name] = true
	}

	// Apply overrides
	for name, enabled := range overrides {
		if enabled {
			targetServices[name] = true
		} else {
			delete(targetServices, name)
		}
	}

	// Sync profiles for profile-aware services
	for _, svc := range o.services {
		if pAware, ok := svc.(interface {
			SetProfile(*profiles.HoneypotProfile)
		}); ok {
			pAware.SetProfile(prof)
		}
	}

	// Stop services that shouldn't be running
	for name, svc := range o.services {
		if svc.IsRunning() && !targetServices[name] {
			log.Printf("[ORCHESTRATOR] Stopping service %s...\n", name)
			svc.Stop()
		}
	}

	// Start services that should be running
	var runningList []string
	for name := range targetServices {
		if svc, ok := o.services[name]; ok {
			if !svc.IsRunning() {
				log.Printf("[ORCHESTRATOR] Starting service %s on port %d...\n", name, svc.Port())
				if err := svc.Start(ctx); err != nil {
					log.Printf("[ORCHESTRATOR] Error starting service %s: %v\n", name, err)
				}
			}
			if svc.IsRunning() {
				runningList = append(runningList, name)
			}
		}
	}

	// Update network parameters & firewall based on running ports
	var activePorts []system.PortProto
	for _, name := range runningList {
		if svc, ok := o.services[name]; ok {
			activePorts = append(activePorts, system.PortProto{
				Port:  svc.Port(),
				Proto: svc.Proto(),
			})
		}
	}

	system.ApplyProfileNetworkSettings(profileName, o.logger, activePorts, o.config.Web.Port, o.config.Web.Enabled)
	o.mangler.SetProfile(profileName)

	// Log orchestrator profile change
	o.logger.Log(map[string]interface{}{
		"service":          "orchestrator",
		"event_type":       "profile_changed",
		"summary":          fmt.Sprintf("Active profile switched to %s.", prof.DisplayName),
		"profile":          profileName,
		"running_services": runningList,
	})
}

func (o *Orchestrator) syncLoop() {
	defer o.wg.Done()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	lastProfile := o.activeProfile
	lastOverridesJson := ""

	for {
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
			dbCtx, dbCancel := context.WithTimeout(context.Background(), 3*time.Second)
			state, err := o.getDBState(dbCtx)
			dbCancel()
			if err != nil {
				continue
			}

			overridesBytes, _ := json.Marshal(state.ServiceOverrides)
			overridesJson := string(overridesBytes)

			// Detect database change
			if state.ActiveProfile != lastProfile || overridesJson != lastOverridesJson {
				log.Printf("[ORCHESTRATOR] DB Sync Loop detected state change (Profile: %s, Overrides: %s)\n", state.ActiveProfile, overridesJson)
				o.mu.Lock()
				o.activeProfile = state.ActiveProfile
				o.overrides = state.ServiceOverrides
				o.applyState(o.ctx, state.ActiveProfile, state.ServiceOverrides)
				o.mu.Unlock()

				lastProfile = state.ActiveProfile
				lastOverridesJson = overridesJson
			}

			// Report currently running services list back to DB if changed
			var currentRunning []string
			o.mu.Lock()
			for name, svc := range o.services {
				if svc.IsRunning() {
					currentRunning = append(currentRunning, name)
				}
			}

			// Compare running lists
			equals := len(currentRunning) == len(state.RunningServices)
			if equals {
				runningMap := make(map[string]bool)
				for _, r := range state.RunningServices {
					runningMap[r] = true
				}
				for _, r := range currentRunning {
					if !runningMap[r] {
						equals = false
						break
					}
				}
			}

			if !equals {
				state.RunningServices = currentRunning
				stateBytes, _ := json.Marshal(state)
				o.db.SaveSystemSetting(o.ctx, "orchestrator_state", string(stateBytes))
			}
			o.mu.Unlock()
		}
	}
}

// ServiceStatus matches the frontend API structure requirements
type WebServiceStatus struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	DisplayHost string `json:"display_host"`
	Template    string `json:"template"`
	Port        int    `json:"port"`
	Running     bool   `json:"running"`
	Enabled     bool   `json:"enabled"`
}

func (o *Orchestrator) GetServicesStatus(displayHost string) []WebServiceStatus {
	// Read state from database to get latest active profile, overrides, and running services
	state, err := o.getDBState(context.Background())
	var activeProfile string
	var overrides map[string]bool
	runningMap := make(map[string]bool)

	if err == nil {
		activeProfile = state.ActiveProfile
		overrides = state.ServiceOverrides
		for _, s := range state.RunningServices {
			runningMap[s] = true
		}
	} else {
		// Fallback to local memory values
		o.mu.Lock()
		activeProfile = o.activeProfile
		overrides = o.overrides
		for name, svc := range o.services {
			if svc.IsRunning() {
				runningMap[name] = true
			}
		}
		o.mu.Unlock()
	}

	// Override displayHost if HONEYPOT_LAN_IP is set
	targetDisplayHost := displayHost
	if lanIP := os.Getenv("HONEYPOT_LAN_IP"); lanIP != "" {
		targetDisplayHost = lanIP
	}

	prof := profiles.GetProfile(activeProfile)
	visible := make(map[string]bool)
	if prof != nil {
		for _, s := range prof.Services {
			visible[s] = true
		}
	}
	for name, enabled := range overrides {
		if enabled {
			visible[name] = true
		}
	}

	var list []WebServiceStatus
	o.mu.Lock()
	defer o.mu.Unlock()

	for name, svc := range o.services {
		if !visible[name] {
			continue
		}

		tmpl := name
		for _, prefix := range []string{"http_", "telnet_", "ssh_", "ftp_"} {
			if strings.HasPrefix(name, prefix) {
				tmpl = prefix[:len(prefix)-1]
				break
			}
		}

		enabled := false
		if cfg, ok := o.config.Services[name]; ok {
			enabled = cfg.Enabled
		}

		list = append(list, WebServiceStatus{
			Name:        name,
			Host:        svc.PortNameHost(),
			DisplayHost: targetDisplayHost,
			Template:    tmpl,
			Port:        svc.Port(),
			Running:     runningMap[name],
			Enabled:     enabled,
		})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})
	return list
}

// Fallback host method implementation in HoneypotService
func (b *BaseTCPService) PortNameHost() string {
	return b.host
}

func (b *BaseUDPService) PortNameHost() string {
	return b.host
}
