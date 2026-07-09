package defense

import (
	"context"
	"log"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/database"
)

type DefenseSystem struct {
	db                 *database.DB
	suspiciousCounters map[string]int
	rateLimits         map[string][]time.Time
	mu                 sync.RWMutex
	onBlacklistHook    func(ip string)
	onUnblacklistHook  func(ip string)
}

func NewDefenseSystem(db *database.DB) *DefenseSystem {
	return &DefenseSystem{
		db:                 db,
		suspiciousCounters: make(map[string]int),
		rateLimits:         make(map[string][]time.Time),
	}
}

func (ds *DefenseSystem) RegisterHooks(onAdd, onDel func(ip string)) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.onBlacklistHook = onAdd
	ds.onUnblacklistHook = onDel
}

func (ds *DefenseSystem) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM whitelist WHERE ip = $1)"
	err := ds.db.Pool.QueryRow(ctx, query, ip).Scan(&exists)
	return exists, err
}

func (ds *DefenseSystem) IsBlacklisted(ctx context.Context, ip string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM blacklist WHERE ip = $1)"
	err := ds.db.Pool.QueryRow(ctx, query, ip).Scan(&exists)
	return exists, err
}

type WhitelistEntry struct {
	IP          string `json:"ip"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

func (ds *DefenseSystem) GetWhitelist(ctx context.Context) ([]WhitelistEntry, error) {
	query := "SELECT ip, description, timestamp FROM whitelist ORDER BY timestamp DESC"
	rows, err := ds.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []WhitelistEntry
	for rows.Next() {
		var entry WhitelistEntry
		var t time.Time
		if err := rows.Scan(&entry.IP, &entry.Description, &t); err != nil {
			return nil, err
		}
		entry.Timestamp = t.UTC().Format("2006-01-02 15:04:05 UTC")
		list = append(list, entry)
	}
	return list, nil
}

func (ds *DefenseSystem) AddToWhitelist(ctx context.Context, ip, desc string) error {
	query := "INSERT INTO whitelist (ip, description, timestamp) VALUES ($1, $2, $3) ON CONFLICT (ip) DO NOTHING"
	_, err := ds.db.Pool.Exec(ctx, query, ip, desc, time.Now().UTC())
	return err
}

func (ds *DefenseSystem) DeleteFromWhitelist(ctx context.Context, ip string) (bool, error) {
	query := "DELETE FROM whitelist WHERE ip = $1"
	tag, err := ds.db.Pool.Exec(ctx, query, ip)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

type BlacklistEntry struct {
	IP          string `json:"ip"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

func (ds *DefenseSystem) GetBlacklist(ctx context.Context) ([]BlacklistEntry, error) {
	query := "SELECT ip, description, timestamp FROM blacklist ORDER BY timestamp DESC"
	rows, err := ds.db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []BlacklistEntry
	for rows.Next() {
		var entry BlacklistEntry
		var t time.Time
		if err := rows.Scan(&entry.IP, &entry.Description, &t); err != nil {
			return nil, err
		}
		entry.Timestamp = t.UTC().Format("2006-01-02 15:04:05 UTC")
		list = append(list, entry)
	}
	return list, nil
}

func (ds *DefenseSystem) AddToBlacklist(ctx context.Context, ip, desc string) error {
	query := "INSERT INTO blacklist (ip, description, timestamp) VALUES ($1, $2, $3) ON CONFLICT (ip) DO NOTHING"
	_, err := ds.db.Pool.Exec(ctx, query, ip, desc, time.Now().UTC())
	if err == nil {
		ds.mu.RLock()
		hook := ds.onBlacklistHook
		ds.mu.RUnlock()
		if hook != nil {
			hook(ip)
		}
	}
	return err
}

func (ds *DefenseSystem) DeleteFromBlacklist(ctx context.Context, ip string) (bool, error) {
	query := "DELETE FROM blacklist WHERE ip = $1"
	tag, err := ds.db.Pool.Exec(ctx, query, ip)
	if err != nil {
		return false, err
	}
	affected := tag.RowsAffected() > 0
	if affected {
		ds.mu.RLock()
		hook := ds.onUnblacklistHook
		ds.mu.RUnlock()
		if hook != nil {
			hook(ip)
		}
	}
	return affected, nil
}

func (ds *DefenseSystem) IsAutoBlacklistEnabled(ctx context.Context) bool {
	var val string
	query := "SELECT setting_value FROM system_settings WHERE setting_key = 'auto_blacklist_enabled'"
	err := ds.db.Pool.QueryRow(ctx, query).Scan(&val)
	if err != nil {
		return true // Default to true if setting missing/error
	}
	return val == "true"
}

func (ds *DefenseSystem) RecordSuspiciousEvent(ctx context.Context, ip string) {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "unknown" {
		return
	}

	if !ds.IsAutoBlacklistEnabled(ctx) {
		return
	}

	whitelisted, err := ds.IsWhitelisted(ctx, ip)
	if err != nil {
		log.Println("Error checking whitelist in defense system:", err)
		return
	}
	if whitelisted {
		return
	}

	ds.mu.Lock()
	ds.suspiciousCounters[ip]++
	count := ds.suspiciousCounters[ip]

	if count >= 100 {
		delete(ds.suspiciousCounters, ip)
		delete(ds.rateLimits, ip)
		ds.mu.Unlock()
		log.Printf("[DEFENSE] IP %s banned: reached 100 suspicious events\n", ip)
		go func() {
			if err := ds.AddToBlacklist(context.Background(), ip, "Automated ban: reached 100 suspicious events"); err != nil {
				log.Println("Error adding IP to blacklist:", err)
			}
		}()
		return
	}

	now := time.Now()
	history := ds.rateLimits[ip]

	var cleanHistory []time.Time
	for _, t := range history {
		if now.Sub(t) < time.Second {
			cleanHistory = append(cleanHistory, t)
		}
	}
	cleanHistory = append(cleanHistory, now)
	ds.rateLimits[ip] = cleanHistory
	ds.mu.Unlock()

	if len(cleanHistory) >= 10 {
		ds.mu.Lock()
		delete(ds.suspiciousCounters, ip)
		delete(ds.rateLimits, ip)
		ds.mu.Unlock()
		log.Printf("[DEFENSE] IP %s banned: rate limit exceeded (10 events/sec)\n", ip)
		go func() {
			if err := ds.AddToBlacklist(context.Background(), ip, "Automated ban: rate limit exceeded (10 events/sec)"); err != nil {
				log.Println("Error adding IP to blacklist:", err)
			}
		}()
	}
}
