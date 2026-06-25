# Honeypot Orchestrator - Memory & Next Steps

## 🏗️ Proje Mimari ve Dosya Yapısı

```text
honeypot-orchestrator/
├── .dockerignore                     # Docker build işleminde dışarıda bırakılacak dosyalar
├── .env                              # Veritabanı parolası, API anahtarları ve şifreleme parolaları
├── .env.example                      # Örnek .env değişken şablonu
├── docker-compose.lan.yml            # Yerel ağ (LAN) ortamı için Docker mikroservis yapılandırması
├── docker-compose.yml                # Prodüksiyon (WAN) ortamı için Docker mikroservis yapılandırması
├── memory.md                         # Projenin genel işleyiş, yol haritası ve arşivi
├── README.md                         # Kurulum ve projenin kullanım talimatları
├── logs/                             # (Dışa aktarılan log dizini)
│   └── honeypot.db                   # Eski SQLite veritabanı (Artık kullanılmıyor, kaldırılabilir)
├── backend/                          # Honeypot tuzakları, tehdit istihbaratı ve API (Python)
│   ├── cli.py                        # Sistemin komut satırı giriş noktası (--mode decoy|system|web|ti)
│   ├── config.yaml                   # Uygulamanın temel ağ, port ve profil yapılandırması
│   ├── defense.py                    # Brute force koruması ve otomatik iptables drop mantığı
│   ├── Dockerfile                    # Tüm backend modülleri için ortak olan Python 3.12 imajı
│   ├── orchestrator.py               # Konteynerler arası senkronizasyon ve servis yöneticisi
│   ├── requirements.txt              # Backend için gerekli Python pip paket listesi
│   ├── test_threat_intel.py          # Threat Intel (TI) modülü için özel geliştirilmiş testler
│   ├── threat_intel.py               # AbuseIPDB, GreyNoise, ASN, rDNS ve Tor zenginleştirme modülü
│   ├── ti_worker.py                  # İstihbarat sorgularını arka planda asenkron çalıştıran worker
│   ├── __init__.py                   # Modül tanım dosyası
│   ├── api/                          # REST API endpoint dizini
│   │   ├── router.py                 # API yönlendiricileri ve genel tanımlamalar
│   │   └── handlers/                 # Endpoint logic'leri (Handler katmanı)
│   │       ├── auth.py               # Login, session kontrolü ve doğrulama işlemleri
│   │       ├── blacklist.py          # IP Karaliste/Beyazliste yönetim endpointleri
│   │       ├── overview.py           # Dashboard istatistik verilerini sağlayan endpoint
│   │       └── services.py           # Servis durumlarını izleme ve yönetme endpointleri
│   ├── certs/                        # Sertifikalar
│   │   └── dummy.pem                 # LDAPS ve diğer SSL destekli tuzaklar için sahte SSL sertifikası
│   ├── core/                         # Sistem çekirdeği araçları
│   │   ├── config.py                 # config.yaml dosyasını parse edip objeye dönüştüren sınıf
│   │   ├── crypto_utils.py           # PBKDF2 hashleme ve AES-GCM şifreleme/çözme fonksiyonları
│   │   ├── event_logger.py           # Olayları DB'ye asenkron kaydeden logger (Lazy init destekli)
│   │   └── geo.py                    # Cache destekli offline/lokal IP Coğrafi Konum çözücü
│   ├── database/                     # Veritabanı katmanı (PostgreSQL)
│   │   ├── database.py               # SQLAlchemy (PostgreSQL / aiosqlite) asenkron veritabanı motoru
│   │   ├── models.py                 # DB tablo şemaları (Events, Sessions, Users, vb.)
│   │   └── repository.py             # API için CRUD operasyonlarını (DB sorgularını) yürüten katman
│   ├── logs/                         # Konteyner içi log dizini
│   │   └── events.jsonl              # Olayların yazıldığı JSON Lines formatlı raw log dosyası
│   ├── scripts/                      # Yardımcı betikler
│   │   ├── generate_secret_key.py    # Güvenli AES (HONEYPOT_SECRET_KEY) üreten betik
│   │   └── start-lan.sh              # Projeyi LAN modunda ayağa kaldıran bash betiği
│   ├── services/                     # Dinamik yüklenen (Plug&Play) honeypot tuzakları
│   │   ├── __init__.py               # Tuzakları SERVICE_REGISTRY içinde toplayan dinamik yükleyici
│   │   ├── base.py                   # Her tuzağın türediği temel base sınıfı (BaseHoneypotService)
│   │   ├── dns.py                    # Sahte DNS tuzağı
│   │   ├── ftp.py                    # Sahte FTP tuzağı
│   │   ├── http.py                   # Sahte HTTP web sunucusu tuzağı
│   │   ├── ldap.py                   # Sahte LDAP tuzağı
│   │   ├── ldaps.py                  # Sahte LDAPS tuzağı
│   │   ├── llmnr.py                  # Sahte LLMNR tuzağı
│   │   ├── mssql.py                  # Sahte Microsoft SQL Server tuzağı
│   │   ├── nbtnns.py                 # Sahte NetBIOS Name Service (NBT-NS) tuzağı
│   │   ├── netbios.py                # Sahte NetBIOS Session Service tuzağı
│   │   ├── rdp.py                    # Sahte Remote Desktop (RDP) tuzağı
│   │   ├── rpc.py                    # Sahte MS-RPC tuzağı
│   │   ├── smb.py                    # Sahte SMB (Server Message Block) tuzağı
│   │   ├── ssh.py                    # Sahte SSH tuzağı
│   │   └── telnet.py                 # Sahte Telnet tuzağı
│   ├── system/                       # Ağ/İşletim sistemi kontrol katmanı
│   │   ├── net_tuner.py              # Linux iptables ile port yönlendirmeleri yapan script
│   │   ├── packet_mangler.py         # NFQueue üzerinden TCP başlıklarını değiştirerek OS Obfuscation yapar
│   │   └── profiles.py               # Windows/Linux honeypot şablonlarını barındıran kurallar
│   ├── tests/                        # Birim (Unit) Testleri
│   │   ├── test_config.py            # Config parsing testleri
│   │   ├── test_defense.py           # Auto-ban ve defense modülü testleri
│   │   ├── test_orchestrator.py      # Orkestratör mekanizması testleri
│   │   ├── test_services.py          # Tuzak servislerinin testleri
│   │   └── test_utils.py             # Yardımcı araç testleri
│   └── web/                          # Honeypot-web mikroservis altyapısı
│       ├── __init__.py               # Modül tanım dosyası
│       ├── server.py                 # aiohttp tabanlı web sunucusu (API ve statik sunucu)
│       └── utils.py                  # Authentication, CSRF token ve rate-limit sağlayan web middleware'leri
└── frontend/                         # Görsel kontrol paneli (React.js SPA)
    ├── Dockerfile                    # Nginx tabanlı frontend sunucu Docker imajı
    ├── index.html                    # Ana kontrol paneli çerçevesi (Modern temaları destekler)
    ├── login.html                    # Kimlik doğrulama giriş sayfası çerçevesi
    ├── nginx.conf                    # Statik dosyaları sunmak ve yönlendirmek için Nginx yapılandırması
    ├── package.json                  # Frontend npm bağımlılık listesi
    ├── vite.config.js                # React uygulaması için Vite yapılandırması
    ├── public/                       # Statik açık dosyalar
    └── src/                          # React kaynak kodları dizini
        ├── common.js                 # Backend ile fetch() wrapper (CSRF ve Session hatalarını çözer)
        ├── login.js                  # Arayüzden bağımsız giriş işlemlerinin yapıldığı logic
        ├── main.js                   # React uygulamasını başlatan root dosyası
        ├── styles.css                # CSS Variable tabanlı 6 farklı temayı barındıran stil
        ├── utils.js                  # Veri formatlama ve ortak yardımcı fonksiyonlar
        └── components/               # React Komponentleri
            ├── App.js                # Ana çerçeve, Sidebar, Header ve sayfa geçişleri
            ├── Core.js               # Sistem istatistikleri ve Threat Intel ayarları (Settings alt paneli)
            ├── Dashboard.js          # 3D Tehdit haritası ve genel servis ekranı
            ├── Live.js               # Anlık akan terminal tabanlı log analiz ekranı
            ├── Logs.js               # Veritabanı filtreli detaylı log arama ekranı
            ├── Profiles.js           # Profil değiştirme ve IP Kara/Beyaz liste yönetimi
            └── Settings.js           # Yönetici ayarları, parola ve tema değiştirme ekranı
```

---
## Completed

### Bug Fixes & Technical Debt (Recently Completed)
1. **Live Activity Monitor Akış Yönü:** En yeni log en üstte olacak şekilde tersine çevrildi.
2. **Unit Test Kapsamı Artırma:** `config.py`, `orchestrator.py` ve `services/base.py` modülleri için temel testler eklendi.
3. **.gitignore Güncelleme:** `.env`, `*.db`, `node_modules/`, `dist/` dosyaları eklendi ve git cache'den temizlendi.
4. **Hatalı Import Düzeltme:** `orchestrator.py` içindeki `net_tuner` yolu düzeltildi.
5. **HONEYPOT_SECRET_KEY:** Yeni anahtar üretildi ve `.env` ile compose dosyalarına eklendi.
6. **Eksik Bağımlılık:** `aiosqlite` paketi `requirements.txt`'ye eklendi.
7. **Deprecated datetime.utcnow:** `models.py` içindeki kullanımlar `datetime.now(timezone.utc)` olarak güncellendi.
8. **Hardcoded Kimlik Bilgileri:** `docker-compose.lan.yml` dosyasındaki bilgiler dinamik `.env` referanslarına alındı.
9. **login.html Tema Uyumsuzluğu:** Login sayfasındaki tema script'i ana sayfayla (6 tema) uyumlu hale getirildi.
10. **Dockerfile Healthcheck:** Sağlık kontrolü Dockerfile'dan kaldırıldı (sadece web konteynerinde çalışıyordu).
11. **Dockerfile Eksik Portlar:** FTP, SSH, MSSQL vb. eksik honeypot servis portları EXPOSE satırına eklendi.
12. **Dead Code Silme:** Kullanılmayan `AppRouter.js` dosyası silindi.
13. **main.js Temizlik:** Kullanılmayan React değişkenleri kaldırıldı.
14. **event_logger.py Init Güvenliği:** `DBEventLogger` sınıfında lazy initialization yapısına geçildi.
15. **Honeypot DB Temizliği:** `logs/honeypot.db` git repo'sundan başarıyla kaldırıldı.
16. **Frontend Split:** `frontend/src/app-react.js` (3037 satır) başarıyla ES bileşenlerine bölündü ve silindi.
17. **Backend Router Ayrışımı:** `web/server.py` modüler handler'lara bölündü (655 satıra düştü).
18. **MITRE Panel Alert & Attacker IP Senkronizasyonu:** `Analyze.js`'deki React closure/timing bug'ı düzeltildi. Sayfa yüklendiğinde tehdit içeren (hits > 0) ilk aşama render anında dinamik olarak seçilerek hem sol tarafta görsel olarak vurgulanması hem de sağ taraftaki Threat Inspector sütununda saldırgan IP adreslerinin anında listelenmesi sağlandı.

### Phase 0 - 9
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
- **Phase 10:** Mimari Sadeleştirme, Frontend Split ve Mikroservis İzolasyonu — Arka plan dizin yapısı katmanlara ayrıldı. `server.py` temizlenerek router-handler yapısına geçildi. 3000+ satırlık devasa `app-react.js` modüler ES bileşenlerine bölündü. Sistem tek parça yerine tam bağımsız 4 mikroservise (`decoy`, `system`, `web`, `ti`) ayrıldı. `honeypot-system` root/NET_ADMIN yetkileriyle network ayarlarını (iptables) devralırken, `honeypot-web` ve `honeypot-ti` tam yetkisiz (non-root) şekilde çalıştırılarak izolasyon sağlandı. Servisler arası iletişim ve state yönetimi PostgreSQL veritabanı üzerinden senkronize hale getirildi. Decoy servisleri `SERVICE_REGISTRY` üzerinden modüler Plug-and-Play altyapısına geçirildi. Dashboard 3D Globe CSS bugı giderildi.
- **Attacker Origins Paneli Taşma & Sidebar Üzerine Gelme Bugı Düzeltildi:** Masaüstü modunda `.sidebar`'a `z-index: 99;` eklenerek panellerin üzerine binmesi engellendi. `.geo-map-panel` (harita paneli) üzerindeki beyaz parlama (shine effect) WebGL uyumluluğu nedeniyle devredışı bırakıldı (`display: none !important;`) ve `isolation: isolate;` eklenerek tarayıcılardaki taşma ve scrollbar tetikleme hatası tamamen çözüldü.
- **3D Harita Durumu:** Kullanıcı tercihi doğrultusunda harita, topoğrafya/bump map ve varsayılan sürekli auto-rotate özellikleri aktif olacak şekilde orijinal ve kararlı varsayılan haline geri döndürüldü.
- **UI & Bugfix Serisi:** `Live.js` üzerindeki liste sıralama (reverse) hatası giderildi. Dashboard'daki "Recent Events" paneli sadece şüpheli olayları (src_ip içeren) gösterecek şekilde filtrelendi ve adı "Recent Suspicious Events" olarak güncellendi.
- **Threat Intel & Test Suite Düzeltmeleri:** `test_threat_intel.py`'nin yerel ortamda SQLite'a düşme hatası giderilip doğrudan Docker Postgres'e (test verileri) yönlendirmesi sağlandı. API key'lerin `.env` değişimi sonrası şifrelenme çakışması (InvalidToken) veritabanı senkronizasyonu ile çözülerek AbuseIPDB ve Greynoise skorlarının `N/A` dönmesi hatası giderildi.
- **Analyze Sayfası Eklendi:** Phase 12'nin hazırlığı olarak, Frontend SPA mimarisine uygun şekilde `/analyze` route'u eklendi ve Threat Intel tablosu Dashboard'dan çıkartılarak bu özel sayfaya taşındı.
- **Öncelikli Görev - İnteraktif `.env` Kurulum Betiği & Gömülü TI Anahtarları:** Tehdit istihbaratı API anahtarları doğrudan yazılım çekirdeğine (`config.py`) gömülerek `.env` sadeleştirildi. `setup.sh` betiği yazıldı; ağ kurulumunu tetikler, şifreleme anahtarını otomatik üretir, kullanıcı adı/şifreyi alır ve `.env` dosyasını hazırlar. Ayrıca `cli.py` içerisinde key rotation mantığı eklenerek şifreleme anahtarı değiştiğinde veritabanındaki şifreli anahtarların otomatik olarak yeni anahtarla yeniden şifrelenip güncellenmesi sağlandı.

---

## To-Do: Phase 11 — Web UI Alerts & SIEM Integration

## !!!!!!TO-DO'DA OLANLARI SANA SÖYLENMEDİĞİ SÜRECE KESİNLİKLE BAŞLAMIYOSUN HİÇ BİR ŞEY YAPMIYOSUN!!!!!!!!!!

**Amaç:** Kullanıcıyı kritik olaylardan arayüz üzerinden anında haberdar etmek ve honeypot loglarını merkezi bir SIEM (Security Information and Event Management) sistemine aktarabilmek.

1. **Web UI Bildirim Sistemi (Frontend & Backend):**
   - Web arayüzünün sağ üst köşesine bir bildirim (çan) ikonu ve açılır menü eklenecek.
   - Sadece "Şüpheli Olaylar" (Suspicious Events / Alerts) için (ör. login_attempt, exploit_attempt) anlık bildirim (toast/pop-up) gösterilecek.
   - Backend tarafında WebSocket veya Server-Sent Events (SSE) ile anlık bildirim akışı sağlanacak.

2. **SIEM Entegrasyon Sayfası (Frontend):**
   - Ayarlar veya özel bir route altında yeni bir "SIEM Integration" sayfası oluşturulacak.
   - **Konfigürasyon Formu:**
     - SIEM Name (ör. Splunk, QRadar, Wazuh)
     - SIEM IP Address
     - Port
     - Protocol (TCP / UDP / HTTP)
     - Log Format (JSON)
     - Scope (Yalnızca Alertler / Tüm Loglar)
   - "Test Connection" butonu ile hedefe örnek bir JSON paketi gönderilip bağlantı test edilebilecek.

3. **SIEM Forwarder Engine (Backend):**
   - Yeni bir `siem_forwarder.py` servisi/modülü yazılacak.
   - `event_logger.py` üzerinden gelen loglar, kullanıcı ayarlarına (Scope) göre filtrelenecek.
   - Filtrelenen loglar asenkron olarak ve belirlenen protokol (TCP/UDP/HTTP) üzerinden SIEM IP/Port adresine basılacak.
   - SIEM konfigürasyonu veritabanında (`SystemSettings`) veya `config.yaml` içinde saklanıp dinamik olarak yüklenecek.

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
