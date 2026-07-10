package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	ID        int             `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Service   string          `json:"service"`
	EventType string          `json:"event_type"`
	SrcIP     *string         `json:"src_ip"`
	SrcPort   *int            `json:"src_port"`
	Summary   *string         `json:"summary"`
	Details   json.RawMessage `json:"details"`
}

type DB struct {
	Pool *pgxpool.Pool
}

func Connect(ctx context.Context, connStr string) (*DB, error) {
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	db := &DB{Pool: pool}
	if err := db.initSchema(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return db, nil
}

func (db *DB) initSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id SERIAL PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			service VARCHAR(255) NOT NULL,
			event_type VARCHAR(255) NOT NULL,
			src_ip VARCHAR(255),
			src_port INTEGER,
			summary TEXT,
			details JSONB
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(255) NOT NULL DEFAULT 'viewer'
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id VARCHAR(255) PRIMARY KEY,
			username VARCHAR(255) NOT NULL,
			role VARCHAR(255) NOT NULL DEFAULT 'viewer',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS whitelist (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(255) UNIQUE NOT NULL,
			description VARCHAR(255),
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS blacklist (
			id SERIAL PRIMARY KEY,
			ip VARCHAR(255) UNIQUE NOT NULL,
			description VARCHAR(255),
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS threat_intel_cache (
			ip VARCHAR(255) PRIMARY KEY,
			data JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS system_settings (
			setting_key VARCHAR(255) PRIMARY KEY,
			setting_value TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
	}

	for _, q := range queries {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			return err
		}
	}

	// Apply migration for existing databases to enlarge VARCHAR(255) setting_val to TEXT
	alterQuery := "ALTER TABLE system_settings ALTER COLUMN setting_value TYPE TEXT;"
	if _, err := db.Pool.Exec(ctx, alterQuery); err != nil {
		// Log error but don't fail startup if column type is already TEXT or alter table is not supported
		fmt.Printf("Database schema migration notice: %v (setting_value type change may already be applied)\n", err)
	}

	return nil
}

func (db *DB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

func (db *DB) InsertEvent(ctx context.Context, evt *Event) error {
	query := `
		INSERT INTO events (timestamp, service, event_type, src_ip, src_port, summary, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`
	var detailsVal interface{}
	if len(evt.Details) > 0 {
		detailsVal = evt.Details
	} else {
		detailsVal = nil
	}

	err := db.Pool.QueryRow(ctx, query,
		evt.Timestamp,
		evt.Service,
		evt.EventType,
		evt.SrcIP,
		evt.SrcPort,
		evt.Summary,
		detailsVal,
	).Scan(&evt.ID)

	return err
}

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
}

type Session struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func (db *DB) GetUser(ctx context.Context, username string) (*User, error) {
	query := "SELECT id, username, password_hash, role FROM users WHERE username = $1"
	u := &User{}
	err := db.Pool.QueryRow(ctx, query, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (db *DB) SaveUser(ctx context.Context, username, passwordHash, role string) error {
	query := `
		INSERT INTO users (username, password_hash, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (username) DO UPDATE
		SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
	`
	_, err := db.Pool.Exec(ctx, query, username, passwordHash, role)
	return err
}

func (db *DB) DeleteUser(ctx context.Context, username string) error {
	query := "DELETE FROM users WHERE username = $1"
	_, err := db.Pool.Exec(ctx, query, username)
	return err
}

func (db *DB) GetAllUsers(ctx context.Context) ([]*User, error) {
	query := "SELECT id, username, role FROM users"
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (db *DB) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	query := "SELECT session_id, username, role, created_at FROM sessions WHERE session_id = $1"
	s := &Session{}
	err := db.Pool.QueryRow(ctx, query, sessionID).Scan(&s.SessionID, &s.Username, &s.Role, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	if time.Since(s.CreatedAt) > 24*time.Hour {
		_ = db.DeleteSession(ctx, sessionID)
		return nil, fmt.Errorf("session expired")
	}
	return s, nil
}

func (db *DB) SaveSession(ctx context.Context, sessionID, username, role string) error {
	query := `
		INSERT INTO sessions (session_id, username, role, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (session_id) DO UPDATE
		SET username = EXCLUDED.username, role = EXCLUDED.role, created_at = EXCLUDED.created_at
	`
	_, err := db.Pool.Exec(ctx, query, sessionID, username, role, time.Now().UTC())
	return err
}

func (db *DB) DeleteSession(ctx context.Context, sessionID string) error {
	query := "DELETE FROM sessions WHERE session_id = $1"
	_, err := db.Pool.Exec(ctx, query, sessionID)
	return err
}

func (db *DB) CleanupExpiredSessions(ctx context.Context) error {
	query := "DELETE FROM sessions WHERE created_at < $1"
	_, err := db.Pool.Exec(ctx, query, time.Now().UTC().Add(-24*time.Hour))
	return err
}

func (db *DB) GetSystemSetting(ctx context.Context, key string) (string, error) {
	query := "SELECT setting_value FROM system_settings WHERE setting_key = $1"
	var val string
	err := db.Pool.QueryRow(ctx, query, key).Scan(&val)
	return val, err
}

func (db *DB) SaveSystemSetting(ctx context.Context, key, value string) error {
	query := `
		INSERT INTO system_settings (setting_key, setting_value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (setting_key) DO UPDATE
		SET setting_value = EXCLUDED.setting_value, updated_at = NOW()
	`
	_, err := db.Pool.Exec(ctx, query, key, value)
	return err
}

func (db *DB) GetThreatIntelBulk(ctx context.Context, ips []string) (map[string]string, error) {
	results := make(map[string]string)
	if len(ips) == 0 {
		return results, nil
	}
	query := "SELECT ip, data FROM threat_intel_cache WHERE ip = ANY($1) AND updated_at > NOW() - INTERVAL '1 hour'"
	rows, err := db.Pool.Query(ctx, query, ips)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ip, data string
		if err := rows.Scan(&ip, &data); err == nil {
			results[ip] = data
		}
	}
	return results, nil
}

func (db *DB) SaveThreatIntel(ctx context.Context, ip string, dataJSON string) error {
	query := `
		INSERT INTO threat_intel_cache (ip, data, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (ip) DO UPDATE
		SET data = EXCLUDED.data, updated_at = NOW()
	`
	_, err := db.Pool.Exec(ctx, query, ip, dataJSON)
	return err
}
