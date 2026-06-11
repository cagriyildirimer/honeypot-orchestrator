# Honeypot Orchestrator - Memory & Next Steps

## Completed So Far
- **Phase 0:** `start_service` / `stop_service` signature bugs fixed. Toggle buttons working.
- **Phase 1 & 2:** GeoIP integration (batching, caching), 3D Interactive World Map (globe.gl), Real-time Events Counter (events/min), Dashboard Event Detail Drawer (Slide-out JSON view).
- **Phase 3:** IP Rate Limiting (Sliding Window, 10 events/sec), Log Rotation (events.jsonl 50MB limit), Session Persistence (survives Docker restarts).

## To-Do: Phase 4 (Next Session)
1. **Password Hashing (Backend):** Passwords are currently plain-text in `web_users.json`. Switch to secure hashing (e.g. `hashlib.pbkdf2_hmac` or `bcrypt`) for login verification and user creation.
2. **Webhook / Notification System (Backend):** Add an alert system (Discord/Telegram/Slack) for critical events (new attacker IP, rate limit exceeded, service crash).
3. **Light Mode (Frontend):** Currently all 6 themes are dark. Implement a clean, modern "Light Mode" for daytime monitoring.
4. **Mobile Responsive Refinements (Frontend):** Sidebar and dashboard grid layout fixes for small screens (hamburger menu).
