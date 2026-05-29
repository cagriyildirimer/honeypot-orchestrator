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

## Protocol Decoy Implementations & Architectural Details
- **HTTP Decoy (`services/http.py`)**: Simulates basic HTTP servers, parses request lines and header structures (e.g. User-Agent), and returns profile-specific mock web pages.
- **SSH Decoy (`services/ssh.py`)**: Emulates banner greetings and password prompts. Logs standard password-based login attempts and yields authentication denials.
- **FTP Decoy (`services/ftp.py`)**: Mimics standard command sequences (USER, PASS, QUIT) and tracks login credentials and interaction logs.
- **DNS Decoy (`services/dns.py`)**: Listens over TCP (port 1053 default), decodes DNS query headers, names, classes, and types (A, CNAME, TXT, etc.), returning structured NXDOMAIN packet responses.
- **NetBIOS Decoy (`services/netbios.py`)**: Decodes NetBIOS-encoded name representations, handles session requests, and logs any follow-up binary payloads.
- **LDAP Decoy (`services/ldap.py`)**: Performs ASN.1/BER decoding, handles authentication bind payloads (generating realistic Active Directory login failures), and supports baseObject/rootDSE searches with dynamic attributes like `currentTime`.
- **LDAPS Decoy (`services/ldaps.py`)**: Reads the initial TLS Client Hello frame to parse the incoming TLS version, then returns a realistic TLS alert payload to gracefully reject further negotiation.
- **MSSQL Decoy (`services/mssql.py`)**: Implements TDS packet headers, pre-login table structures, and parses Login7 packets to dynamically extract credentials and return highly realistic, username-interpolated SQL Server authentication failures (`Login failed for user '{username}'.`).
- **RDP Decoy (`services/rdp.py`)**: Decodes standard TPKT frames, parses incoming `Cookie: mstshash` routing tokens, and closes connections with negotiation failure packets.
- **SMB Decoy (`services/smb.py`)**: A robust custom state machine supporting both SMB1 and SMB2 protocols, including SPNEGO token encapsulation, NTLM challenge-response sequences, and NTLMSSP payload decoding (Domain/Username/Workstation).
- **Live Attacker Monitor (`/live` Page)**: A terminal-like, real-time command monitoring dashboard built directly into the Web UI. It polls targeted honeypot events at 1.5-second intervals, providing instant operational feedback of attacker connections, inputs, and commands in a premium JetBrains Mono font face. External Webhooks/Telegram integrations were removed per user specifications to keep operational views fully self-contained.

