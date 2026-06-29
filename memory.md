# Honeypot Orchestrator - Memory & Next Steps

---
## 🔍 TAM KOD DENETİM RAPORU

> **Tarih:** 2026-06-29  
> **Kapsam:** Tüm frontend (JS/CSS/HTML) + backend (Python) + Docker/CI kaynak kodları  
> **Toplam dosya:** ~45 kaynak dosya, ~15.000 satır backend + ~7.000 satır frontend  
> **Toplam bulgu:** 29 sorun + 10 öneri



---

### 1. KRİTİK HATALAR

**🔴 BUG-01: `Live.js` — Döngüsel Import**
- **Dosya:** `frontend/src/components/Live.js:4`
- **Sorun:** `import { App } from './App.js';` satırı var ama `App` hiçbir yerde kullanılmıyor. `App.js` zaten `Live.js`'i import ettiği için döngüsel bağımlılık var.
- **Etki:** Modül initialization sırası karışabilir, özellikle production build'de.
- **Çözüm:** Import satırını sil.

**🔴 BUG-02: `styles.css` — Çift `.toast` Tanımı**
- **Dosya:** `frontend/src/styles.css` — Satır 1873-1897 ve 3363-3414
- **Sorun:** `.toast` CSS sınıfı iki farklı yerde tanımlı. Eski tanım `position: sticky; bottom: 16px`, yeni tanım `position: fixed !important; top: 24px !important`. Eski tanımdaki `font-weight: 800` ve border/background stilleri cascade'de kalıyor.
- **Çözüm:** Satır 1873-1897 arasındaki eski `.toast`, `.toast.success`, `.toast.error` bloklarını tamamen sil.

**🟢 BUG-03: `common.js` — CSRF Token Tek Kullanımlık Olmalı (ÇÖZÜLDÜ)**
- **Dosya:** `frontend/src/common.js:1-50`
- **Sorun:** CSRF token bir kez fetch edilip global `csrfToken` değişkeninde saklanıyor ve her POST isteğinde tekrar kullanılıyor. Backend tarafında token'lar 24 saat geçerli kalıyor (`overview.py:24`). CSRF token'lar normalde tek kullanımlık (nonce) olmalıdır.
- **Etki:** Token replay saldırısına açık. Bir saldırgan tek bir CSRF token'ı yakalasa 24 saat boyunca kullanabilir.
- **Çözüm:** Her POST isteği öncesi yeni token al, ya da backend'de kullanılan token'ları geçersiz kıl.

**🟢 BUG-04: `_save_users` — Tüm Kullanıcıları Sil-Yaz Paterni (Race Condition) (ÇÖZÜLDÜ)**
- **Dosya:** `backend/web/utils.py:127-139`
- **Sorun:** `_save_users()` önce `DELETE FROM users` yapıp sonra yeniden INSERT ediyor. İki admin aynı anda kullanıcı oluşturma/silme yaparsa birinin değişiklikleri kaybolur.
- **Etki:** Veri kaybı riski.
- **Çözüm:** DELETE-all yerine upsert (MERGE) veya tek satır DELETE/INSERT kullan.

---

### 2. GÜVENLİK AÇIKLARI

**🟢 SEC-01: SIEM Endpoint'lerinde Admin Kontrolü Yok (ÇÖZÜLDÜ)**
- **Dosya:** `backend/api/handlers/settings.py:33-54`
- **Sorun:** `/api/settings/siem` POST ve `/api/settings/siem/test` POST endpoint'leri sadece `_is_authenticated` kontrolü yapıyor. `_is_admin` kontrolü eksik.
- **Etki:** "viewer" rolündeki bir kullanıcı SIEM ayarlarını değiştirebilir ve dışarıya veri sızdırabilir.
- **Çözüm:** Her iki handler'a `if not server._is_admin(request["cookies"]): return server._forbidden_response()` ekle.

**🟢 SEC-02: API Anahtarları Kaynak Kodda Gömülü (ÇÖZÜLDÜ)**
- **Dosya:** `backend/core/config.py:97-98`
- **Sorun:** AbuseIPDB API key ve GreyNoise API key, `config.py` içinde default value olarak hardcoded yazılmış. Git repo'sunda açıkta.
- **Etki:** API key'lerin kötüye kullanılma riski. Public repo'ya konulursa ciddi sorun.
- **Çözüm:** Default value olarak boş string koy, sadece `.env` üzerinden yükle.

**🟢 SEC-03: Cookie'de `Secure` Flag Eksik (ÇÖZÜLDÜ)**
- **Dosya:** `backend/web/utils.py:178-182`
- **Sorun:** Session cookie `HttpOnly` ve `SameSite=Strict` içeriyor ama `Secure` flag eksik.
- **Etki:** Man-in-the-middle saldırısıyla session hijacking riski.
- **Çözüm:** HTTPS kullanıldığında `Secure` flag'i ekle.


**🟢 SEC-04: `is_blacklisted` — Her Sorguda `resolve_mac` Çağırılıyor (ÇÖZÜLDÜ)**
- **Dosya:** `backend/database/repository.py:75-91`
- **Sorun:** `is_blacklisted()` her çağrıda `resolve_mac(ip)` çalıştırıyor. Bu fonksiyon `subprocess.check_output(["arp", ...])` ile dış komut çalıştırıyor. Her gelen honeypot event'inde çağrılıyor olabilir.
- **Etki:** Performans darboğazı + her event'te subprocess fork'u.
- **Çözüm:** MAC sonuçlarını cache'le veya blacklist kontrolünde MAC aramasını kaldır.

**⚠️ UYARI: Web Arayüzünde MAC Adreslerinin Görünmeme Sorunu**
- **Sorun:** Web arayüzünde bazı listelerde veya loglarda MAC adresleri gösterilmiyor/görünmüyor.
- **Yapılacak İşlem:** frontend tarafındaki tablo bileşenleri ve backend'in gönderdiği event payload'ları incelenerek MAC adreslerinin UI'a ulaşıp ulaşmadığı tespit edilecek ve düzeltilecek.


**🟢 SEC-05: `read_recent_events` — `r.details.update()` ile Kontrol Edilmemiş Alanlar (ÇÖZÜLDÜ)**
- **Dosya:** `backend/web/utils.py:35-36`
- **Sorun:** `event_data.update(r.details)` satırı, DB'deki JSON `details` alanının tüm key-value çiftlerini ana event dict'ine karıştırıyor. `details` içinde `"service"`, `"event_type"` gibi key'ler varsa, üst seviye değerleri override eder.
- **Etki:** Veri bütünlüğü sorunu.
- **Çözüm:** `details` alanını ayrı bir key altında döndür veya çakışan key'leri filtrele.

---

### 3. ÖLÜ KOD ve KALINTI

**DEAD-01: `common.js` — `setText` Fonksiyonu**
- **Dosya:** `frontend/src/common.js:121-128`
- **Sorun:** `setText()` fonksiyonu `window.setText` olarak dışa aktarılmış ama React SPA'da hiçbir yerde çağrılmıyor. Eski vanilla JS kalıntısı.
- **Çözüm:** Sil.

**DEAD-02: `common.js` — `applyRoleVisibility` Fonksiyonu**
- **Dosya:** `frontend/src/common.js:195-200`
- **Sorun:** `applyRoleVisibility()` fonksiyonu `[data-admin-only]` DOM elementlerini arıyor ama React SPA'da böyle elementler yok.
- **Çözüm:** Sil veya login.js'e taşı.

**DEAD-03: `common.js` — `initializeThemeControls` Gereksiz Listener**
- **Dosya:** `frontend/src/common.js:100-112`
- **Sorun:** `[data-theme-toggle]` butonları için click listener ekliyor. React SPA'da böyle butonlar yok. `AppearancePage` kendi state yönetimini yapıyor.
- **Çözüm:** Login.html'de kullanılmıyorsa sil.

**DEAD-04: `test_cpu.py` — Geçici Test Dosyası**
- **Dosya:** `backend/test_cpu.py`
- **Sorun:** Root seviyede gereksiz test dosyası. Production'a deploy edilebilir.
- **Çözüm:** Sil veya `tests/` dizinine taşı.

---

### 4. ÇALIŞMAYAN / BOŞ MANTIK

**EMPTY-01: `siem_forwarder.py` — HTTP URL Mantık Hatası**
- **Dosya:** `backend/core/siem_forwarder.py:57-65`
- **Sorun:** HTTP protokolü dalında URL oluşturma mantığı hatalı. İlk `url = f"http://..."` ataması yapılıp hemen ardından aynı koşul kontrol ediliyor — ilk atama gereksiz.
- **Çözüm:** Tekrar eden atamayı kaldır, sadece if/else bırak.

**EMPTY-02: `orchestrator.py` — `start_service` Boş `pass` Bloğu**
- **Dosya:** `backend/orchestrator.py:196-198`
- **Sorun:** `start_service` metodu içinde `pass` ile boş bırakılmış bir blok var. System mode'da servis başlatma talebi gelmesine rağmen network ayarları anında uygulanmaz.
- **Etki:** System mode'da 3 saniyelik sync döngüsünü beklemek zorunda.
- **Çözüm:** Pass'ı kaldır, açık yorum bırak veya sync'i tetikle.

**EMPTY-03: `defense.py` — `_suspicious_counters` Hiç Resetlenmiyor**
- **Dosya:** `backend/defense.py:92-93` ve `:105-106`
- **Sorun:** Ban edilen IP'nin counter'ı sıfırlanmıyor. Counter 101, 102... devam ediyor. Her event'te tekrar `add_to_blacklist` çağrılır (gereksiz DB sorguları).
- **Etki:** Bellek sızıntısı + gereksiz DB yükü.
- **Çözüm:** Ban sonrası counter'ı sıfırla veya sil.

---

### 5. KOD KALİTESİ SORUNLARI

**QUALITY-01:** `Dashboard.js:154` — `"Suspicios Events"` yazım hatası → `"Suspicious Events"` olmalı.

**QUALITY-02:** `Live.js:43-60` — User Pill Eksik. Diğer tüm sayfalarda topbar'da "Signed in as admin" pill'i var. Live sayfasında yok.

**QUALITY-03:** `Live.js` — Logout Butonu Stil Tutarsızlığı. Live sayfasında `"button secondary"`, diğer sayfalarda `"button"` (primary).

**QUALITY-04:** `Core.js:322-336` — NotificationBell Hardcoded Renkler. Dropdown menüsü `background: "#1e1e1e"`, `color: "#888"` gibi hardcoded renkler kullanıyor. Tema değişkenlerini (`var(--surface)`, `var(--border)`) kullanmıyor.

**QUALITY-05:** `index.html:22` — CSP İhlali Riski. `<script src="https://unpkg.com/globe.gl">` harici CDN. Backend CSP `script-src 'self'` diyor. Ayrıca inline script de `unsafe-inline` olmadan çalışmaz.

**QUALITY-06:** `styles.css` — 3416 Satır / 70KB. Tek CSS dosyası. İçinde duplike tema tanımları var.

**QUALITY-07:** `Settings.js:516-577` — ResourceGauge bileşeni tüm stillerini inline style olarak tanımlıyor. CSS dosyasında karşılığı yok.

---

### 6. PERFORMANS

**PERF-01:** `server.py:378-379` — CPU Ölçümü 200ms Blokaj. Her settings API isteğinde `await asyncio.sleep(0.2)` çağrılıyor. 5 saniyede bir poll = her poll'de 200ms blokaj. **Çözüm:** Arka plan task'ıyla periyodik ölç, cache'le.

**PERF-02:** `Core.js:255-256` — MutationObserver Tüm DOM İzleniyor. `observer.observe(document.body, { childList: true, subtree: true })` — her DOM mutasyonunda `querySelector` çalışıyor. **Çözüm:** Daha dar scope veya debounce.

**PERF-03:** `utils.py:19-41` — Her API İsteğinde DB Sorgusu. Overview, analyze, threat-intel, stats, events — hepsi ayrı DB sorgusu. Dashboard 5 saniyede bir poll yapıyor. **Çözüm:** Kısa süreli (5-10 sn) bellekte cache.

**PERF-04:** `siem_forwarder.py:51-56` — Her Event İçin TCP Bağlantısı. TCP modunda her event için yeni bağlantı açılıp kapatılıyor. **Çözüm:** Persistent TCP connection veya batching.

---

### 7. ÖNERİLER ve FİKİRLER

1. **Credential Harvest Raporu** — Tüm login denemelerinden `username/password` çiftlerini toplayan panel. "En çok denenen şifreler", "Saldırganların kullandığı username'ler".
2. **IP Bazlı Attack Timeline** — Bir IP seçildiğinde tüm hareketlerinin kronolojik zaman çizelgesi.
3. **Dashboard Light Mode** — Şu an 6 koyu tema var. Bir de açık (light) tema eklenebilir.
4. **Log Arama İyileştirmesi** — Alan bazlı arama (IP, service, event_type) ve regex desteği.
5. **Honeypot Decoy Dosyaları** — FTP ve SMB'ye sahte dosya sistemleri (`passwords.xlsx`, `backup.sql`, `.ssh/id_rsa`). Canary token mantığı.
6. **Email/Webhook Alert** — Kritik alert'ler için email veya webhook (Slack, Discord, Telegram) entegrasyonu.
7. **Rate Limiting Dashboard** — Hangi IP'lerin rate limit'e takıldığını gösteren panel.
8. **Custom Profile Builder UI** — GUI ile yeni profil oluşturma. Kullanıcı hangi servislerin açık olacağını seçip kendi profilini kaydeder.
9. **GeoIP Heatmap (2D)** — SVG bazlı 2D dünya haritası üzerinde ülke bazlı renk yoğunluk haritası. 3D Globe'a hafif alternatif.
10. **Otomatik Backup ve Export** — Zamanlanmış otomatik log export (günlük/haftalık JSONL veya CSV backup).

---

### 📊 Özet Tablo

| Kategori | Kritik | Orta | Düşük | Toplam |
|----------|--------|------|-------|--------|
| Hatalar (Bug) | 4 | 0 | 0 | **4** |
| Güvenlik | 2 | 3 | 0 | **5** |
| Ölü Kod | 0 | 4 | 0 | **4** |
| Boş Mantık | 0 | 3 | 0 | **3** |
| Kod Kalitesi | 0 | 0 | 7 | **7** |
| Performans | 0 | 2 | 2 | **4** |
| **TOPLAM** | **6** | **12** | **9** | **27** |

> **Önerilen Aksiyon Sırası:**
> 1. SEC-01 (SIEM admin kontrolü) + SEC-02 (API key'leri koda gömme) — **hemen düzelt**
> 2. BUG-01 (döngüsel import) + BUG-02 (çift toast) — **kolay düzeltme**
> 3. BUG-03 (CSRF token reuse) + BUG-04 (user save race) — **güvenlik iyileştirmesi**
> 4. EMPTY-01/02/03 — **mantık düzeltmeleri**
> 5. Ölü kod temizliği — **bakım**

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
