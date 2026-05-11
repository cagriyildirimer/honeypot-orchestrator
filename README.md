# Honeypot Orchestrator

Lab-only fake honeypot orchestrator for defensive testing.

## Run

No external Python package is required for the current MVP.

```bash
python -m honeypot_orchestrator.cli --config config.yaml
```

Dashboard:

```text
http://127.0.0.1:8000
```

Default login:

- Username: `admin`
- Password: `admin123`

Behavior:

- On startup, only the web dashboard opens.
- Honeypot services are started and stopped from the dashboard.

Available services:

- HTTP honeypot: `127.0.0.1:8080`
- Fake SSH login: `127.0.0.1:2222`
- FTP banner/login: `127.0.0.1:2121`
- Telnet login: `127.0.0.1:2323`

Events are written to `logs/events.jsonl`.

## Docker

The project is ready to run in Docker and Docker Compose.

Docker Compose:

```bash
docker compose up --build
```

Plain Docker:

```bash
docker build -t honeypot-orchestrator .
docker run --rm -p 8000:8000 -p 8080:8080 -p 2222:2222 -p 2121:2121 -p 2323:2323 \
  -e HONEYPOT_HOST=0.0.0.0 \
  -e HONEYPOT_WEB_HOST=0.0.0.0 \
  -e HONEYPOT_AUTH_USERNAME=admin \
  -e HONEYPOT_AUTH_PASSWORD=admin123 \
  -e HONEYPOT_LOG_PATH=/app/logs/events.jsonl \
  -v honeypot_logs:/app/logs \
  honeypot-orchestrator
```

Container notes:

- The container listens on `0.0.0.0` through environment overrides.
- Logs are written to `/app/logs/events.jsonl` inside the container.
- The web health endpoint is available at `/healthz`.
- Config values can be overridden with environment variables such as:
  - `HONEYPOT_WEB_PORT`
  - `HONEYPOT_AUTH_USERNAME`
  - `HONEYPOT_AUTH_PASSWORD`
  - `HONEYPOT_SERVICE_HTTP_PORT`
  - `HONEYPOT_SERVICE_SSH_ENABLED`

## Safety Boundary

This project is for defensive lab use only. It does not include real exploit code,
malware behavior, credential reuse, attack automation, or backdoor behavior.
