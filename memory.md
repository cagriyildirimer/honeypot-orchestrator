# Project Memory

- Main Python package lives in `honeypot_orchestrator/`; there is no separate backend/frontend tree anymore.
- The app is intentionally dependency-light: config parsing, HTTP dashboard serving, and protocol decoys are implemented with the standard library.
- Service classes are registered in `honeypot_orchestrator/services/__init__.py` via `SERVICE_REGISTRY`; orchestrator lifecycle logic should not duplicate that registry.
- Profiles live in `honeypot_orchestrator/profiles.py`; `empty` is the safe startup profile and opens no honeypot listeners.
- Web UI is served from `honeypot_orchestrator/web/templates/` and `honeypot_orchestrator/web/static/`; `app-react.js` is a no-build React SPA loaded from vendored React files.
- Dashboard auth is session-cookie based and stores local users in `logs/web_users.json`; default admin comes from config/env.
- Event logs are JSONL at `logs/events.jsonl` locally or `/app/logs/events.jsonl` in Docker.
- Tests live in `tests/` and can be run with `py -m unittest discover`.
- Use `py -m ...` on this Windows workspace; plain `python` may hit the Microsoft Store alias.
- Extra root folders `backend/`, `frontend/`, and `vision-ui-upstream/` were removed because they were unused/untracked leftovers.
- Current target branch for pushing is `origin/main`.
