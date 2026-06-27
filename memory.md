# Honeypot Orchestrator - Memory & Next Steps

---
## ⚠️ ÖNCELİKLİ YAPILACAKLAR (Kod Denetim Raporu)

> **Tarih:** 2026-06-26  
> **Kapsam:** Tüm frontend (JS/CSS) + backend (Python) kaynak kodları incelendi.

### 🔴 KRİTİK HATALAR

> ✅ **Tümü çözüldü** (2026-06-27)


### 🟠 ORTA ÖNCELİK SORUNLARI

5. **`settings.py` Handler — Admin Yetkisi Kontrolü Eksik**  
   - **Dosya:** `backend/api/handlers/settings.py:33-54`  
   - **Sorun:** `/api/settings/siem` POST endpoint'i sadece `_is_authenticated` kontrolü yapıyor ama `_is_admin` kontrolü yapmıyor. Viewer rolündeki bir kullanıcı SIEM ayarlarını değiştirebilir. Aynı sorun `/api/settings/siem/test` için de geçerli.  
   - **Çözüm:** `if not server._is_admin(request["cookies"]): return server._forbidden_response()` ekle.

6. **`server.py` — `_handle_clear_logs` Çağrılmıyor (Dead Code)**  
   - **Dosya:** `backend/web/server.py:204-207`  
   - **Sorun:** `_handle_clear_logs` metodu tanımlı ama hiçbir route tarafından çağrılmıyor. Eski bir kalıntı.  
   - **Çözüm:** Ya bir route'a bağla ya da sil.

7. **`server.py` — `_export_logs_response` Çağrılmıyor (Dead Code)**  
   - **Dosya:** `backend/web/server.py:456-467`  
   - **Sorun:** `_export_logs_response` metodu tanımlı ama router'da kayıtlı bir endpoint yok. Log export fonksiyonu erişilemez durumda.  
   - **Çözüm:** `/api/logs/export` gibi bir route kaydet veya sil.

8. **`test_cpu.py` — Root Seviyede Test Dosyası**  
   - **Dosya:** `backend/test_cpu.py`  
   - **Sorun:** Bu geçici bir test dosyası. Proje root'unda gereksiz yer kaplıyor.  
   - **Çözüm:** Sil veya `tests/` dizinine taşı.

9. **`Core.js` — `NotificationBell` Dropdown Menü Tema Uyumsuzluğu**  
   - **Dosya:** `frontend/src/components/Core.js:290-304`  
   - **Sorun:** Bildirim dropdown menüsü hardcoded renkler kullanıyor: `background: "#1e1e1e"`, `border: "1px solid #333"`, `color: "#888"` vs. Bu renkler tema CSS değişkenlerini kullanmıyor. Farklı temalarda (özellikle Slate Mono) kötü görünür.  
   - **Çözüm:** `var(--surface)`, `var(--border)`, `var(--muted)` gibi CSS değişkenleri kullan.

10. **`Core.js` — `NotificationBell` MutationObserver Performans Riski**  
    - **Dosya:** `frontend/src/components/Core.js:223-224`  
    - **Sorun:** `MutationObserver` tüm `document.body`'yi `childList: true, subtree: true` ile izliyor. Her DOM değişikliğinde `querySelector` çalışıyor. Büyük sayfalarda (Dashboard, Analyze) her render'da tetiklenir.  
    - **Çözüm:** `subtree: true` yerine daha dar bir hedef kullan veya debounce ekle.

### 🟡 DÜŞÜK ÖNCELİK / KOD KALİTESİ

11. **`Dashboard.js:154` — Yazım Hatası**  
    - **Sorun:** `"Suspicios Events"` yazıyor, doğrusu `"Suspicious Events"` olmalı.  
    - **Çözüm:** Düzelt.

12. **`index.html` — CSP İhlali Riski**  
    - **Dosya:** `frontend/index.html:22`  
    - **Sorun:** `<script src="https://unpkg.com/globe.gl">` harici bir CDN'den yükleniyor. Backend'in gönderdiği CSP header'ı (`script-src 'self'`) bu kaynağı engelliyor. Tarayıcı konsolunda CSP ihlal hatası üretir (Nginx proxy üzerinden sunulduğu için şu an sorun olmayabilir ama doğrudan backend'e bağlanıldığında çalışmaz).  
    - **Çözüm:** Globe.js'i vendor dizinine indir veya CSP'ye `https://unpkg.com` ekle.

13. **`common.js` — `setText` ve `applyRoleVisibility` Kullanılmıyor**  
    - **Dosya:** `frontend/src/common.js:121-128` ve `:195-200`  
    - **Sorun:** `setText` fonksiyonu ve `applyRoleVisibility` fonksiyonu tanımlı ve `window`'a atanmış ama React SPA'da hiçbir yerde çağrılmıyor. Eski vanilya JS kalıntısı.  
    - **Çözüm:** Sil.

14. **`common.js` — `initializeThemeControls` Gereksiz DOM Event Listener**  
    - **Dosya:** `frontend/src/common.js:100-110`  
    - **Sorun:** `[data-theme-toggle]` butonları için click listener ekliyor ama React SPA'da böyle butonlar yok. `AppearancePage` kendi state'ini yönetiyor. Bu kod hala sayfa yüklendiğinde çalışıyor ama hiçbir etkisi yok.  
    - **Çözüm:** Bu fonksiyonu kaldır veya sadece login.html için bırak.

15. **`Live.js:57` — Logout Butonu Stil Tutarsızlığı**  
    - **Dosya:** `frontend/src/components/Live.js:56-59`  
    - **Sorun:** Live sayfasındaki logout butonu `className: "button secondary"` kullanıyor. Diğer tüm sayfalarda logout butonu `className: "button"` (primary) kullanıyor. Tutarsız.  
    - **Çözüm:** Diğer sayfalarla aynı yap: `className: "button"`.

16. **`Live.js` — User Pill Eksik**  
    - **Dosya:** `frontend/src/components/Live.js:43-60`  
    - **Sorun:** Live sayfasının topbar-actions bölümünde `user-pill` (Signed in as) bileşeni yok. Diğer tüm sayfalarda var.  
    - **Çözüm:** Ekle.

17. **`server.py` — `_build_settings_payload` CPU Ölçümü 200ms Blokaj**  
    - **Dosya:** `backend/web/server.py:378-379`  
    - **Sorun:** CPU kullanım yüzdesi hesaplamak için `await asyncio.sleep(0.2)` çağrılıyor. Her settings API isteğinde 200ms blokaj oluyor. System sayfası 5 saniyede bir poll yapıyor — sorun küçük ama gereksiz yavaşlatma.  
    - **Çözüm:** Arka plan task'ı ile periyodik olarak CPU ölç ve cache'le. API isteğinde cache'ten dön.

18. **`styles.css` — 3416 Satır / 70KB Boyut**  
    - **Sorun:** Tek bir CSS dosyası 70KB. İçinde duplike tanımlar var (eski/yeni toast, dark tema duplicate). Bakımı zorlaştırıyor.  
    - **Çözüm:** İleride bileşen bazlı CSS'e bölünebilir.

19. **`server.py:250` — CSP `script-src` Sorunu**  
    - **Dosya:** `backend/web/server.py:250`  
    - **Sorun:** CSP header `script-src 'self'` diyor ama `index.html` inline script (`<script>try { var savedTheme...`) içeriyor. Bu `unsafe-inline` olmadan çalışmaz. Frontend Nginx üzerinden sunulduğu için backend CSP bypass ediliyor ama güvenlik açısından tutarsız.  
    - **Çözüm:** Inline script'i ayrı bir dosyaya taşı veya nonce-based CSP kullan.

20. **`ResourceGauge` — Inline Style Yığını**  
    - **Dosya:** `frontend/src/components/Settings.js:518-644`  
    - **Sorun:** Gauge bileşeni tüm stillerini inline style olarak tanımlıyor. CSS dosyasında karşılığı yok. Bu bakımı zorlaştırıyor ve tema değişikliklerinde sorun çıkarabilir.  
    - **Çözüm:** CSS sınıflarına taşı.

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
1. **Kritik: `Live.js` Döngüsel Import Silindi:** Kullanılmayan `import { App } from './App.js';` satırı kaldırıldı. App.js zaten Live.js'i import ettiğinden döngüsel bağımlılık riski ortadan kalktı.
2. **Kritik: `styles.css` Çift `.toast` Tanımı Temizlendi:** Satır 1873-1897 arasındaki eski `.toast`, `.toast.success`, `.toast.error` blokları silindi. Yalnızca yeni (fixed, top) tanım kaldı.
3. **Kritik: `ResourceGauge` `colorClass` Prop Aktifleştirildi:** Ölü olan `colorClass` prop'u artık destructure ediliyor ve gauge arka plan track renginde (opacity 0.15) kullanılıyor.
4. **Kritik: `ResourceGauge` Gauge Yönü Doğrulandı:** SVG `rotate(-180deg)` + `strokeDashoffset` formülü soldan sağa dolduruyor — yön doğru, kod değişikliği gerekmedi.
5. **Görsel: Login Ekranı Glassmorphism & Splash Animasyonu:** Giriş ekranı, referans tasarımla tam uyumlu olacak şekilde baştan tasarlandı. `backdrop-filter: blur(35px) saturate(1.5)` ile buzlu cam (glassmorphism) etkisi uygulandı. Arka plana 3D küreler (derinlikli radial gölgelendirmelerle), hareket eden neon sıvı küreler (tüm temalarla uyumlu renklerde), çizgili retro-fütüristik desenler eklendi. Şifre göster/gizle ikonu, stilize checkbox, ve başlangıçta siber temalı boot-up animasyonu yapan yükleme ekranı (durum mesajları ve "Intro Geç" butonuyla) entegre edildi.
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
19. **setup.sh & start-lan.sh Macvlan .env Hatası:** `start-lan.sh` içindeki `REPO_ROOT` değişkeninin yanlışlıkla `backend` dizinini göstermesi nedeniyle `HONEYPOT_LAN_IP` değerinin yanlış `.env` dosyasına (repository root yerine `backend/.env` içine) yazılması sorunu giderildi. `REPO_ROOT` iki üst dizine (`../../`) yönlendirilerek hem `.env` dosyasının hem de `docker-compose` dosyalarının doğru dizinde çalışması sağlandı. Ayrıca `setup.sh` içindeki varsayılan seçim, arayüzdeki öneriyle uyumlu olarak 2 (Macvlan) olarak güncellendi.
20. **SIEM / aiohttp Bağımlılık ve 502 Hatası Düzeltildi:** SIEM entegrasyonu (Phase 11) kapsamında geliştirilen `siem_forwarder.py` içindeki `aiohttp` kütüphanesinin `requirements.txt` dosyasında eksik olması nedeniyle, backend konteyneri ayağa kalkarken `ModuleNotFoundError` hatası fırlatarak çöküyor ve bu durum Nginx üzerinde **502 Bad Gateway** hatasına yol açıyordu. `aiohttp` bağımlılığı `requirements.txt` dosyasına eklendi, tüm backend imajları yeniden derlendi ve konteynerler sorunsuz şekilde çalışır hale getirildi.
21. **Bildirim Çanı Konumlandırması Düzeltildi:** Arayüzün sağ üstünde sabit (fixed) olarak duran Bildirim Çanı (`NotificationBell`), React Portal altyapısına geçirilerek (`NotificationBellPortal`) her sayfanın kendi `page-actions` veya `topbar-actions` alanına dinamik olarak dahil edildi. Çan butonu boyutu `38px`'e düşürülerek "Refresh" ve "Log out" butonlarıyla mükemmel şekilde hizalandı. Bu sayede sayfa geçişlerinde oturum ve SSE bağlantı durumu kesilmeden çanın görsel konumu her sayfanın kendi aksiyon alanına taşınmış oldu.

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
- **Phase 12:** MITRE ATT&CK Mapping + Analyze Sayfası — Honeypot verilerinin profesyonel güvenlik çerçevesinde analiz edilebilmesi için `mitre.py` modülü yazıldı. Event type'lar MITRE taktik ve tekniklerine eşlendi. Frontend tarafında `/analyze` route'u ve `/api/analyze` endpoint'i tamamlanarak Threat Heatmap, MITRE ATT&CK Matrix ve Country Breakdown başarıyla sisteme entegre edildi.
- **Phase 11:** Web UI Alerts & SIEM Integration — Sağ üst köşeye okunmamış bildirimleri gösteren rozetli bir Bildirim Çanı eklendi. Hız ve yoğunluğa dayalı akıllı kümeleme (rate-based throttling) yapan Server-Sent Events (SSE) tabanlı gerçek zamanlı uyarı sistemi kuruldu. Ayrıca `siem_forwarder.py` yazılarak honeypot loglarının eşzamanlı olarak UDP, TCP veya HTTP üzerinden dış bir SIEM sistemine (Wazuh, Splunk vb.) iletilmesi sağlandı. Kullanıcı için "SIEM Integration" ayarlar arayüzü kodlandı.

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

## 💭 Düşünülecek: Backend'in Go Diline Geçişi

> **Durum:** Yapılmayacak ama ileride değerlendirilecek. Referans olarak burada tutuluyor.

### Neden Düşünülüyor

- **Performans:** Python asyncio (tek thread, cooperative) → Go goroutine (preemptive, çok çekirdekli). Honeypot = düşük seviye TCP/UDP = Go'nun doğal alanı.
- **Bellek:** Python runtime ~80-120MB → Go statik binary ~15-30MB (5-6x azalma).
- **Deploy:** Docker + pip + runtime bağımlılıkları → Tek statik binary. Docker imajı 10MB'a düşer. `embed.FS` ile frontend tek binary'ye gömülebilir.
- **Startup:** Python ~2-3 saniye → Go ~50ms.
- **Tip güvenliği:** Runtime duck typing hataları → derleme zamanı hata yakalama.

### Riskler ve Zorluklar

- **Efor:** 16 ayrı honeypot servisi var. Özellikle `smb.py` (38KB) ve `ssh.py` (23KB) protokol düzeyinde binary parsing yapıyor. Tamamını çevirmek 2-3 haftalık yoğun iş.
- **ORM kaybı:** SQLAlchemy ORM → `pgx`/`sqlx` ile raw SQL. Daha hızlı ama daha fazla boilerplate.
- **Kütüphaneler:** AbuseIPDB/GreyNoise entegrasyonu, GeoIP, PBKDF2 hashing — Go karşılıkları var ama yeniden yazılması gerekir.
- **Geliştirme hızı:** Python'da iterasyon çok hızlı. Go'da daha fazla kod yazılır ama daha sağlam çalışır.

### Kademeli Geçiş Planı (Eğer yapılırsa)

| Aşama | Kapsam | Gerekçe |
|-------|--------|---------|
| Faz 1 | Honeypot tuzak servisleri (`services/`) | En çok performans kazancı. Raw TCP/UDP dinleyiciler Go'nun güçlü yanı. |
| Faz 2 | Web API (`server.py` + `handlers/`) | `net/http` + `chi` router. Python'daki custom HTTP parser'dan kurtulunur. |
| Faz 3 | Orchestrator + system modülleri | iptables yönetimi, profil sistemi. |

> Frontend (React SPA) aynen kalır — Go tarafından statik dosya olarak sunulur.
