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

## Security & Defense Mechanisms (`defense.py`)
- **IP & MAC Banning**: Provides manual and automated filtering of attackers. Ban list persists in `logs/blacklist.json` while safe clients persist in `logs/whitelist.json`.
- **MAC Address Resolution (`resolve_mac`)**: Dynamically queries the local ARP table using subprocess commands:
  - Windows: Runs `arp -a <ip>` and extracts physical address via regex matching.
  - Linux/macOS: Runs `arp -n <ip>` and extracts physical address.
  - Returns `N/A` for loopback addresses, `unknown` on failure.
- **Automated IP Banning**: If a connection client registers 100 or more suspicious events/connection attempts, it triggers an automated ban entry added to the blacklist.
- **Pre-Connection Filter**: The orchestrator's TCP service base handler passes incoming sockets through a blacklist check first; matching IP or resolved MAC addresses have their connections abruptly closed prior to any protocol interaction.

## Network Tuning & Fingerprint Emulation (`net_tuner.py`)
- **OS Emulation**: Modifies system-level TCP/IP parameters inside the container network namespace to match target profiles:
  - **`windows_server` profile**: Set IP default Time to Live (TTL) to `128`, disable TCP Timestamps (`tcp_timestamps=0`), enable TCP Window Scaling (`tcp_window_scaling=1`) and TCP SACK (`tcp_sack=1`), and set receive/send buffers (`tcp_rmem` and `tcp_wmem`) default values to `65536` to emulate a typical Windows TCP initial window configuration.
  - **`linux_server` / `empty` profiles**: Set IP default TTL to `64`, enable TCP Timestamps (`tcp_timestamps=1`), enable TCP Window Scaling (`tcp_window_scaling=1`) and TCP SACK (`tcp_sack=1`), and restore standard Linux buffer limits.
- **Implementation**: Writes values directly to namespaced sysctl paths under `/proc/sys/net/ipv4/` (specifically `ip_default_ttl`, `tcp_timestamps`, `tcp_window_scaling`, `tcp_sack`, `tcp_rmem`, and `tcp_wmem`). If these paths are unavailable (due to permission limits or OS differences), warnings are gracefully logged without crashing the orchestrator process.

## Web Dashboard & User RBAC (`web/server.py`)
- **Custom Web Server**: Implements a standard-library-only TCP socket listener handling basic HTTP framing, cookie routing, static file parsing, and JSON API payloads.
- **Role-Based Access Control (RBAC)**:
  - **`admin` role**: Full access to all endpoints. Required to modify the active profile, add/delete whitelist or blacklist entries, clear logs, and perform user management operations.
  - **`viewer` role**: Read-only access to log events stream, overview charts, active profiles overview, and status checks. Unauthorized actions return a `403 Forbidden` response.
- **User Management**: Allows admins to dynamically create, delete, alter roles, and change passwords for users. Credentials store in `logs/web_users.json`. A minimum of one admin user is enforced to prevent locking out.

## Protocol Decoy Implementations & Architectural Details
- **HTTP Decoy (`services/http.py`)**: Simulates basic HTTP servers, parses request lines and header structures (e.g. User-Agent), and returns profile-specific mock web pages.
- **SSH Decoy (`services/ssh.py`)**: Emulates banner greetings (e.g. OpenSSH or OpenSSH for Windows) and password prompts. Logs standard password-based login attempts and yields authentication denials.
- **FTP Decoy (`services/ftp.py`)**: Mimics standard command sequences (USER, PASS, QUIT) and tracks login credentials and interaction logs.
- **Telnet Decoy (`services/telnet.py`)**: Simulates basic Telnet authentication, capturing connection attempts, usernames, and passwords while returning standard authentication failures.
- **DNS Decoy (`services/dns.py`)**: Listens over TCP (port 1053 default), decodes DNS query headers, names, classes, and types (A, CNAME, TXT, etc.), returning structured NXDOMAIN packet responses.
- **LLMNR Decoy (`services/llmnr.py`)**: Listens over UDP (port 5355 default), decodes LLMNR query headers and names, and returns spoofed IP address responses to direct query sources back to the honeypot host.
- **NBTNS Decoy (`services/nbtnns.py`)**: Listens over UDP (port 137 default). Handles NetBIOS Name Service queries:
  - **Name Query (0x0020)**: Returns a spoofed name resolution mapping response.
  - **Node Status Query / NBSTAT (0x0021)**: Returns realistic server details including Windows host (`WIN-SRV2019`), Domain (`CORP`), and MAC Address (`00:15:5d:a1:b2:c3`).
- **NetBIOS Decoy (`services/netbios.py`)**: Decodes NetBIOS-encoded name representations, handles session requests, and logs any follow-up binary payloads.
- **LDAP Decoy (`services/ldap.py`)**: Performs ASN.1/BER decoding, handles authentication bind payloads (generating realistic Active Directory login failures), and supports baseObject/rootDSE searches with dynamic attributes like `currentTime`.
- **LDAPS Decoy (`services/ldaps.py`)**: Reads the initial TLS Client Hello frame to parse the incoming TLS version, then returns a realistic TLS alert payload to gracefully reject further negotiation.
- **MSSQL Decoy (`services/mssql.py`)**: Implements TDS packet headers, pre-login table structures, and parses Login7 packets to dynamically extract credentials and return highly realistic, username-interpolated SQL Server authentication failures (`Login failed for user '{username}'.`).
- **RDP Decoy (`services/rdp.py`)**: Decodes standard TPKT frames, parses incoming `Cookie: mstshash` routing tokens, and closes connections with negotiation failure packets.
- **SMB Decoy (`services/smb.py`)**: A robust custom state machine supporting both SMB1 and SMB2 protocols, including SPNEGO token encapsulation, NTLM challenge-response sequences, and NTLMSSP payload decoding (Domain/Username/Workstation).
- **Live Attacker Monitor (`/live` Page)**: A terminal-like, real-time command monitoring dashboard built directly into the Web UI. It polls targeted honeypot events at 1.5-second intervals, providing instant operational feedback of attacker connections, inputs, and commands in a premium JetBrains Mono font face. External Webhooks/Telegram integrations were removed per user specifications to keep operational views fully self-contained.

## LAN / Macvlan Deployment Mode (`scripts/start-lan.sh`)
- **Macvlan Network Mode**: Enables the honeypot orchestrator container to act as a physical device on the host's LAN network by registering its own MAC address and obtaining a dedicated IP address directly from the subnet.
- **Automated setup script (`scripts/start-lan.sh`)**:
  - Automatically identifies default gateways, parent interface interfaces, and subnets.
  - Generates/updates `.env` network variables.
  - Creates the custom docker macvlan network (default name `honeypot_lan_net`).
  - Launches `docker-compose.lan.yml` in detached or interactive mode.
  - Enables binding of decoy services to actual standard ports (HTTP `80`, SSH `22`, SMB `445`, DNS `53`, FTP `21`, Telnet `23`) inside the container namespace without clashing with host processes.
