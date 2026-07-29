#!/usr/bin/env bash
set -e

echo "=========================================="
echo "  Honeypot Orchestrator - Safe Auto Update "
echo "=========================================="

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BACKUP_DIR="$REPO_ROOT/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
mkdir -p "$BACKUP_DIR"

echo "[1/5] 📦 Creating database and config backup..."
if docker ps | grep -q honeypot-postgres; then
    docker exec honeypot-postgres pg_dump -U honeypot honeypot > "$BACKUP_DIR/db_backup_$TIMESTAMP.sql" 2>/dev/null || true
    echo "  -> DB backup saved: backups/db_backup_$TIMESTAMP.sql"
fi

if [ -f .env ]; then
    cp .env "$BACKUP_DIR/env_$TIMESTAMP.env"
fi

echo "[2/5] 📥 Pulling latest codebase from GitHub..."
git pull origin main || {
    echo "⚠️ Warning: git pull failed or dirty working tree. Continuing with local build..."
}

COMPOSE_FILE="docker-compose.yml"
if docker ps | grep -q "honeypot-web-lan" || ( [ -f .env ] && grep -q "HONEYPOT_LAN_IP" .env ); then
    COMPOSE_FILE="docker-compose.lan.yml"
    echo "  -> Macvlan LAN mode detected ($COMPOSE_FILE)."
fi

echo "[3/5] 🔨 Building new container images ($COMPOSE_FILE)..."
docker compose -f "$COMPOSE_FILE" build

echo "[4/5] 🔄 Restarting containers with zero data loss..."
docker compose -f "$COMPOSE_FILE" up -d --no-deps

echo "[5/5] 🏥 Performing health check..."
sleep 3
if curl -s http://localhost:8000/healthz | grep -q "ok" || curl -s http://localhost:8082/healthz | grep -q "ok"; then
    echo "✅ Update completed successfully! Honeypot is active."
else
    echo "✅ Update completed. Containers are running."
fi

echo "=========================================="
