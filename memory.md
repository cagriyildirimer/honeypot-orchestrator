# Honeypot Orchestrator - Memory & Next Steps

## Completed So Far
- **Phase 0:** `start_service` / `stop_service` signature bugs fixed. Toggle buttons working.
- **Phase 1 & 2:** GeoIP integration (batching, caching), 3D Interactive World Map (globe.gl), Real-time Events Counter (events/min), Dashboard Event Detail Drawer (Slide-out JSON view).
- **Phase 3:** IP Rate Limiting (Sliding Window, 10 events/sec), Log Rotation (events.jsonl 50MB limit), Session Persistence (survives Docker restarts).
- **Phase 4:** Password Hashing (Backend) - PBKDF2-HMAC-SHA256 password hashing with auto-migration of plain-text passwords on startup/login.

## To-Do: Phase 4 (Next Session)
1. **Webhook / Notification System (Backend):** Add an alert system (Discord/Telegram/Slack) for critical events (new attacker IP, rate limit exceeded, service crash).
2. **Light Mode (Frontend):** Currently all 6 themes are dark. Implement a clean, modern "Light Mode" for daytime monitoring.
3. **Mobile Responsive Refinements (Frontend):** Sidebar and dashboard grid layout fixes for small screens (hamburger menu).
