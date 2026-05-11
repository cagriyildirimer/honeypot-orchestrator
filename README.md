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

Default services:

- HTTP honeypot: `127.0.0.1:8080`
- Fake SSH login: `127.0.0.1:2222`
- FTP banner/login: `127.0.0.1:2121`
- Telnet login: `127.0.0.1:2323`

Events are written to `logs/events.jsonl`.

## Safety Boundary

This project is for defensive lab use only. It does not include real exploit code,
malware behavior, credential reuse, attack automation, or backdoor behavior.
