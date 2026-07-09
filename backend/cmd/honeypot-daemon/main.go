package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"honeypot-orchestrator/backend/internal/config"
	"honeypot-orchestrator/backend/internal/database"
	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/services"
	_ "honeypot-orchestrator/backend/internal/services/tcp"
	_ "honeypot-orchestrator/backend/internal/services/udp"
	"honeypot-orchestrator/backend/internal/siem"
	"honeypot-orchestrator/backend/internal/system"
	"honeypot-orchestrator/backend/internal/web"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config.yaml file")
	flag.Parse()

	log.Println("Starting Go Honeypot Daemon (Faz 1)...")

	appCfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v\n", err)
	}
	log.Printf("Configuration loaded successfully. Active profile: %s\n", appCfg.Profile)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := database.Connect(ctx, appCfg.DBURL)
	if err != nil {
		log.Fatalf("Database connection failed: %v\n", err)
	}
	defer db.Close()
	log.Println("Database connection established.")

	// Initialize default admin user if not present
	if _, err := db.GetUser(context.Background(), appCfg.Auth.Username); err != nil {
		hashed, err := web.HashPassword(appCfg.Auth.Password)
		if err == nil {
			_ = db.SaveUser(context.Background(), appCfg.Auth.Username, hashed, "admin")
			log.Printf("Default admin user '%s' pre-created in database.\n", appCfg.Auth.Username)
		}
	}

	defenseSys := defense.NewDefenseSystem(db)
	defenseSys.RegisterHooks(
		func(ip string) {
			system.ApplyFirewallRule(ip)
		},
		func(ip string) {
			system.RemoveFirewallRule(ip)
		},
	)
	siemForwarder := siem.NewForwarder(db)
	siemForwarder.Sync(context.Background())

	eventLogger := logger.NewEventLogger(db, 1000, siemForwarder)
	defer eventLogger.Close()

	// Initialize and start central Orchestrator
	orch := services.NewOrchestrator(db, appCfg, eventLogger, defenseSys)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	if err := orch.Start(runCtx); err != nil {
		log.Fatalf("Failed to start Honeypot Orchestrator: %v\n", err)
	}
	defer orch.Stop()

	if appCfg.Web.Enabled {
		srv := web.NewServer(db, appCfg, eventLogger, defenseSys, orch, siemForwarder)
		go func() {
			if err := srv.StartServer(runCtx); err != nil {
				log.Printf("Web API Server error: %v\n", err)
			}
		}()
	}

	eventLogger.Log(map[string]interface{}{
		"service":    "orchestrator",
		"event_type": "started",
		"summary":    "Go Honeypot Daemon started.",
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %v. Gracefully shutting down...\n", sig)

	eventLogger.Log(map[string]interface{}{
		"service":    "orchestrator",
		"event_type": "stopping",
		"summary":    "Go Honeypot Daemon stopping.",
	})

	log.Println("Honeypot shutdown complete.")
}
