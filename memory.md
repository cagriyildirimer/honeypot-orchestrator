# Honeypot Orchestrator - Memory & Next Steps

## Completed
- **Phase 0:** `start_service` / `stop_service` signature bugs fixed. Toggle buttons working.
- **Phase 1 & 2:** GeoIP integration (batching, caching), 3D Interactive World Map (globe.gl), Real-time Events Counter (events/min), Dashboard Event Detail Drawer (Slide-out JSON view).
- **Phase 3:** IP Rate Limiting (Sliding Window, 10 events/sec), Log Rotation (events.jsonl 50MB limit), Session Persistence (survives Docker restarts).
- **Phase 4:** Password Hashing (Backend) - PBKDF2-HMAC-SHA256 password hashing with auto-migration of plain-text passwords on startup/login.
- **Phase 5:** Threat Intelligence Enrichment — `threat_intel.py` modülü (rDNS, ASN/Org, Tor Exit Node, Cloud Provider CIDR, AbuseIPDB, GreyNoise), TI Dashboard Panel (summary pills + top 10 attacker tablosu), `config.yaml` TI key desteği, kapsamlı `test_threat_intel.py` test suite.
- **Phase 6:** Güvenlik Hardening & Teknik Borç — Secret management (`.env`), session TTL & frontend oto-logout, memory leak fix (`defense.py` cleanup), GeoIP kod duplikasyonu çözümü, lazy import temizliği.
- **Phase 7:** Kontrol Paneli Güvenlik Güncellemeleri — Brute Force koruması (5 hata/5 dk), POST istekleri için CSRF Token, HTTP güvenlik başlıkları eklendi.
- **Phase 9:** IOC Export (CSV + STIX 2.1) — Tehdit istihbarat verilerinin dışa aktarımı eklendi.
- **Phase 8 (Adım 1):** Mikroservis İzolasyonu — Backend servisi `honeypot-daemon` (tuzaklar) ve `honeypot-web` (API) olarak ikiye bölündü. Frontend portu 80'e alındı. Docker compose ağ yapılandırmaları ayrıldı.

- **Phase 8 (Adım 2):** PostgreSQL Veritabanı Migrasyonu — Dosya tabanlı mimariden PostgreSQL'e geçiş, SQL tablolarının oluşturulması (Events, Sessions, Users, ThreatIntelCache) ve veri taşıma betiği.
- **Phase 10:** Mimari Sadeleştirme, Teknik Borç ve Frontend Split — Arka plan dizin yapısı katmanlara (`api/`, `core/`, `database/`, `services/`, `system/`) ayrıldı, veritabanı sorguları repository katmanına taşındı. `server.py` temizlenerek router-handler yapısına geçildi. 3000+ satırlık devasa `app-react.js` dosyası modüler ES bileşenlerine bölündü, eski kodlar silindi. Dashboard 3D Globe haritasının genişleme/taşma (resize loop) CSS bugı giderildi. `start-lan.sh` betiğindeki decoy konteyner adı uyuşmazlığı çözüldü.

---

## To-Do: Phase 10 — Mikroservis Mimarisine Geçiş & Mimari Sadeleştirme (ÖNCELİKLİ)

> [!IMPORTANT]
> **En Kritik Nokta:** Bu geçiş aşamasında sistemdeki hiçbir özelliğin (tuzaklar, web paneli, loglama, engelleme, veritabanı akışı vb.) bozulmaması, her şeyin tamamen kesintisiz ve kararlı çalışmaya devam etmesi en önemli önceliğimizdir!

1. **Decoy'ların (Tuzakların) Modüler Hale Gelmesi:**
   - Bal küpü servislerinin (SMB, LDAP, HTTP vb.) `orchestrator.py` bağımlılıklarını gevşetmek.
   - Her bir decoy servisini bağımsız çalışan (Plug & Play) eklenti veya bağımsız süreç modülü haline getirmek.

3. **Mikroservis Mimarisine Geçiş (Konteyner Seviyesinde İzolasyon):**
   - Tüm decoy servislerini (SSH, SMB, FTP, HTTP vb.) tek tek ayrı konteynerlerde çalıştırmak yerine, tamamını barındıran tek bir **`decoy-services`** konteyneri tasarlamak.
   - Sistem seviyesinde ağ ve güvenlik duvarı işlemlerini yöneten `net_tuner` / `packet_mangler` kodlarını, bu decoy servislerinden tamamen ayırıp yetkili bir **`system-controller`** (`privileged: true` / `NET_ADMIN`) mikroservisinde çalıştırmak.
   - `honeypot-web` (Dashboard & API) servisini tamamen yetkisiz (non-root) şekilde çalıştırmak.
   - Konteynerler arası emir ve durum senkronizasyonunu veritabanı veya mesaj kuyruğu üzerinden güvenli hale getirmek.

---

## To-Do: Phase 11 — Webhook / Notification System

**Amaç:** Kritik olaylarda anında bildirim alabilmek.

1. **Config:** `config.yaml`'a `notifications` bölümü ekle:
   ```yaml
   notifications:
     discord_webhook: ""
     telegram_bot_token: ""
     telegram_chat_id: ""
     slack_webhook: ""
     enabled_events:
       - login_attempt
       - auto_ban
       - profile_changed
       - rate_limit_exceeded
   ```
2. **Notification Engine (Backend):** Yeni `notifications.py` modülü. Async HTTP POST ile webhook'lara mesaj gönderimi. Rate limiting (aynı event tipi için min 30 sn aralık). Retry mekanizması (max 2 deneme).
3. **Event Hook Entegrasyonu:** `event_logger.py`'ye hook sistemi ekle. Log yazıldığında `enabled_events` listesindeki event type'lar için notification tetikleme.
4. **Frontend:** Settings'e yeni "Notifications" sayfası. Webhook URL'lerini girme, test butonu ("Send Test Notification"), event filtresi toggle'ları.

---

## To-Do: Phase 12 — MITRE ATT&CK Mapping + Analyze Sayfası

**Amaç:** Honeypot verilerini profesyonel güvenlik çerçevesinde analiz edebilmek.

1. **MITRE ATT&CK Mapping (Backend):** Yeni `mitre.py` modülü. Event type → ATT&CK taktik/teknik eşlemesi.
2. **Analyze Sayfası (Frontend):** Yeni `/analyze` route (Threat Heatmap, MITRE ATT&CK Matrix, Country Breakdown).
3. **API Endpoint:** `/api/analyze` — MITRE mapping, ülke breakdown, servis dağılımı verilerini döner.

---

## To-Do: Phase 13 — Credential Harvest & Attack Timeline Replay

**Amaç:** Saldırgan davranışlarını detaylı izleyebilmek.

1. **Credential Harvest Raporu (Backend + Frontend):** Tüm login denemelerinden `username/password` çiftlerini toplayan liste ve Dashboard paneli.
2. **Attack Timeline Replay (Frontend):** Belirli bir IP seçildiğinde o IP'nin tüm aktivitelerinin kronolojik zaman çizelgesi.
3. **API Endpoint:** `/api/attacker/<ip>` — Tek IP'nin tüm event'leri + TI enrichment + timeline verileri.

---

## To-Do: Phase 14 — Custom Profile Builder & Honeypot File Traps

**Amaç:** Kullanılabilirliği artırmak ve daha sofistike tuzak mekanizmaları eklemek.

1. **Custom Profile Builder (Frontend + Backend):** Dashboard üzerinden yeni profil oluşturma GUI'si.
2. **Honeypot File Traps (FTP + SMB):** FTP ve SMB servislerine sahte ama gerçekçi görünen dosya/dizin yapısı ekleme (`passwords.xlsx` vb.). Canary token mantığı.
3. **Light Mode (Frontend):** CSS variable tabanlı modern light theme.

---

## Teknik Borç (Her Phase Arasında Çözülebilir)
- [ ] `web/server.py` (1282 satır) modüler parçalama: `handlers/`, `utils.py` ayrıştırması.
- [ ] `frontend/src/app-react.js` (3037 satır / 119KB) dosya bölünmesi veya Vite+React migration.
- [ ] Unit test kapsamı artırma: services, orchestrator, config parsing, defense modülü testleri.
- [ ] Live Activity Monitor akış yönü düzeltmesi (En yeni log en üstte olacak şekilde tersine çevrilecek).
