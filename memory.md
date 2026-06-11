# Honeypot Orchestrator - Memory & Next Steps

## Completed So Far
- **Phase 0:** `start_service` / `stop_service` signature bugs fixed. Toggle buttons working.
- **Phase 1 & 2:** GeoIP integration (batching, caching), 3D Interactive World Map (globe.gl), Real-time Events Counter (events/min), Dashboard Event Detail Drawer (Slide-out JSON view).
- **Phase 3:** IP Rate Limiting (Sliding Window, 10 events/sec), Log Rotation (events.jsonl 50MB limit), Session Persistence (survives Docker restarts).
- **Phase 4:** Password Hashing (Backend) - PBKDF2-HMAC-SHA256 password hashing with auto-migration of plain-text passwords on startup/login.

## To-Do: Phase 5 — Threat Intelligence + IOC Export
1. **Threat Intelligence Enrichment (Backend):** Yeni `threat_intel.py` modülü — sadece top 10 harici IP enrichment'a tabi tutulur. Local/private IP'ler + honeypot'un kendi subnet'i (ilk 2 oktet'ten otomatik algılanır) API'ye gönderilmez.
   - Reverse DNS (`socket.getfqdn()`) — ücretsiz, local
   - ASN/Org (ip-api.com'dan `as`+`org` alanları) — ücretsiz, zaten kullanıyoruz
   - Tor Exit Node (torproject.org açık listesi, günde 1 indirme) — ücretsiz, local
   - Cloud Provider (AWS/GCP/Azure/DO/OVH/Linode CIDR listesi) — ücretsiz, gömülü
   - AbuseIPDB skoru (opsiyonel, key gerekli, 1000/gün limit) — key yoksa "N/A"
   - GreyNoise sınıfı (opsiyonel, key gerekli, 50/gün limit) — key yoksa "N/A"
   - Tüm sonuçlar 1 saat in-memory cache'lenir
2. **TI Dashboard Panel (Frontend):** Globe'un hemen altına ayrı panel — summary pills (Tor/Cloud/Avg Abuse) + top 10 attacker tablosu (IP, Location, rDNS, ASN, Tor🧅, Cloud, Abuse Score bar, GreyNoise badge, Event Count). Globe'a dokunulmaz.
3. **IOC Export (Backend + Frontend):** Settings/System sayfasına 2 buton eklenir (mevcut Export JSONL yanına):
   - Export IOC (CSV) → `honeypot-iocs.csv`
   - Export IOC (STIX 2.1) → `honeypot-iocs.stix.json`
4. **Config:** `config.yaml`'a opsiyonel `threat_intel.abuseipdb_key` ve `greynoise_key` alanları.

## To-Do: Phase 6 (Sonraki Session)
1. **Webhook / Notification System (Backend):** Discord/Telegram/Slack alert sistemi.
2. **Light Mode (Frontend):** Modern light theme.
3. **Analyze Sayfası (Frontend):** TI verisi yoğunlaşırsa ayrı sayfaya taşıma (Threat Heatmap, Country Breakdown, MITRE ATT&CK mapping).
