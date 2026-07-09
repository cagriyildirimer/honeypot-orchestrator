# Honeypot Orchestrator - Memory & Next Steps

## 📋 To-Do & Next Steps

### 1. Phase 14 — Honeypot Decoy Files & Canary Tokens
**Amaç:** Daha gerçekçi tuzak dosyalarıyla sızma girişimlerini tespit etmek.
- `[ ]` **Sahte Dosya Sistemi:** FTP ve SMB servislerine sahte dosya yapıları (`passwords.xlsx`, `backup.sql`, `.ssh/id_rsa`) yüklenmesi.
- `[ ]` **Canary Tokens:** Bu decoy dosyalara erişildiğinde tetiklenen özel kritik alarm mekanizması.

### 2. Kapsamlı Kod Denetimi Bulguları (Yeni Go Mimarisi Sorunları)
- `[ ]` **DNS UDP Desteği:** `dns.go`'yu `BaseTCPService` yerine `BaseUDPService` yapısına taşımak, UDP 1053 portunu docker-compose ve dockerfile üzerinde açmak.
- `[ ]` **DoS / OOM Sınırlandırması:** `smb.go` (`readNbssFrame`) ve `netbios.go` (`handleClient`) içindeki sınırsız `make([]byte, length)` bellek tahsisini (max 64KB/128KB limit koyarak) engellemek.
- `[ ]` **AlertStreamer Context Sızıntısı:** `ServeHTTP` içindeki `as.Start(context.Background())` yerine daemon lifecycle context'ini bağlamak.
- `[ ]` **SIEM TCP Reconnect Desteği:** Bağlantı kesildiğinde log kayıplarını engellemek için retry mekanizması eklemek.

---

## 🏗️ Proje Mimari ve Dosya Yapısı (Mevcut Durum)

```
honeypot-orchestrator/
├── docker-compose.yml                 # Standart Go + Postgres + React Çoklu-Mikroservis Konfigürasyonu
├── docker-compose.lan.yml             # LAN Modu için Macvlan Destekli Go + React Konfigürasyonu
├── setup.sh                           # İnteraktif IP, şifreleme ve veritabanı ayarlarını yapan kurulum betiği
├── .env.example                       # Çevre değişkenleri şablon dosyası
├── config.yaml                        # API yetkilendirme, veritabanı ve SIEM hedeflerini barındıran konfigürasyon
├── backend/                           # Go tabanlı Decoy & API daemon dizini
│   ├── cmd/
│   │   └── honeypot-daemon/
│   │       └── main.go                # Go backend uygulamanın giriş noktası (bootstrap)
│   ├── internal/                      # Go iç paketleri (dışarıya kapalı)
│   │   ├── config/                    # Go yapılandırma okuyucu katmanı
│   │   ├── database/                  # pgx tabanlı veritabanı havuzu, loglayıcı
│   │   ├── defense/                   # Bağımsız IP engelleme ve autoblock kontrol katmanı
│   │   ├── logger/                    # Bellek kuyruğu destekli asenkron loglayıcı
│   │   ├── profiles/                  # Aktif decoy servis profilleri (Linux / Windows)
│   │   ├── services/                  # Merkezi servis yöneticisi (Orchestrator) ve base yapılar
│   │   │   ├── base.go
│   │   │   ├── orchestrator.go
│   │   │   ├── tcp/                   # TCP decoy servisleri (http, ssh, ftp, telnet, rdp, smb, rpc, ldap, ldaps, mssql, netbios)
│   │   │   └── udp/                   # UDP decoy servisleri (dns, llmnr, nbtnns)
│   │   ├── siem/                      # UDP/TCP/HTTP SIEM log yönlendirici motoru
│   │   ├── system/                    # iptables firewall yönetimi ve sysctl parametre güncelleyici
│   │   └── web/                       # go-chi router, CSRF/Auth middleware'ler ve JSON API uç noktaları
│   ├── Dockerfile                     # Alpine tabanlı Go daemon derleme ve çalıştırma Dockerfile'ı
│   ├── go.mod
│   └── go.sum
└── frontend/                         # Görsel kontrol paneli (React.js SPA)
    ├── Dockerfile                    # Nginx tabanlı frontend sunucu Docker imajı
    ├── index.html                    # Ana kontrol paneli çerçevesi (Modern temaları destekler)
    ├── login.html                    # Kimlik doğrulama giriş sayfası çerçevesi
    ├── nginx.conf                    # Statik dosyaları sunmak ve yönlendirmek için Nginx yapılandırması
    ├── package.json                  # Frontend npm bağımlılık listesi
    ├── vite.config.js                # React uygulaması için Vite yapılandırması
    ├── public/                       # Statik açık dosyalar
    │   └── vendor/                   # Üçüncü parti statik kütüphaneler (React, globe.gl, theme-loader)
    └── src/                          # React kaynak kodları dizini
        ├── common.js                 # Backend ile fetch() wrapper (CSRF ve Session hatalarını çözer)
        ├── login.js                  # Arayüzden bağımsız giriş işlemlerinin yapıldığı logic
        ├── main.js                   # React uygulamasını başlatan root dosyası
        ├── styles.css                # CSS Variable tabanlı 6 farklı temayı barındıran stil
        ├── utils.js                  # Veri formatlama ve ortak yardımcı fonksiyonlar
        └── components/               # React Komponentleri
            ├── Analyze.js            # Tehdit ısı haritası ve MITRE ATT&CK matrisi ekranı
            ├── App.js                # Ana çerçeve, Sidebar, Header ve sayfa geçişleri
            ├── Core.js               # Sistem istatistikleri, bildirimler ve ortak bileşenler
            ├── Dashboard.js          # 3D Tehdit haritası ve genel servis ekranı
            ├── Live.js               # Anlık akan terminal tabanlı log analiz ekranı
            ├── Logs.js               # Veritabanı filtreli detaylı log arama ekranı
            ├── Profiles.js           # Profil değiştirme ve IP Kara/Beyaz liste yönetimi
            └── Settings.js           # Yönetici ayarları, parola, tema ve SIEM yapılandırma ekranı
```

---

## 💭 Düşünülecek: Backend'in Go Diline Geçişi (Tarihsel Referans)

> **Durum:** Tamamlandı. Geliştirme feature/go-migration dalında sürdürülmüştür. Referans amacıyla burada tutuluyor.

- **Performans:** Python asyncio (tek thread, cooperative) → Go goroutine (preemptive, çok çekirdekli).
- **Bellek:** Python runtime ~80-120MB → Go statik binary ~15-30MB (5-6x azalma).
- **Deploy:** Docker + pip + runtime bağımlılıkları → Tek statik binary.
- **Startup:** Python ~2-3 saniye → Go ~50ms.
- **Tip güvenliği:** Runtime duck typing hataları → derleme zamanı hata yakalama.

---

## Completed

### YAPILAN TÜM İŞLEMLER BURAYA NOT ALINACAKTIR!!!!

1. **Kritik: `Live.js` Döngüsel Import Silindi:** Kullanılmayan `import { App } from './App.js';` satırı kaldırıldı. App.js zaten Live.js'i import ettiğinden döngüsel bağımlılık riski ortadan kalktı.
2. **Kritik: `styles.css` Çift `.toast` Tanımı Temizlendi:** Satır 1873-1897 arasındaki eski `.toast`, `.toast.success`, `.toast.error` blokları silindi. Yalnızca yeni (fixed, top) tanım kaldı.
3. **Kritik: `ResourceGauge` `colorClass` Prop Aktifleştirildi:** Ölü olan `colorClass` prop'u artık destructure ediliyor ve gauge arka plan track renginde (opacity 0.15) kullanılıyor.
4. **Kritik: `ResourceGauge` Gauge Yönü Doğrulandı:** SVG `rotate(-180deg)` + `strokeDashoffset` formülü soldan sağa dolduruyor — yön doğru, kod değişikliği gerekmedi.
5. **Görsel: Login Ekranı Glassmorphism & Splash Animasyonu:** Giriş ekranı, referans tasarımla tam uyumlu olacak şekilde baştan tasarlandı. `backdrop-filter: blur(35px) saturate(1.5)` ile buzlu cam (glassmorphism) etkisi uygulandı. Arka plana 3D küreler, hareket eden neon sıvı küreler, çizgili retro-fütüristik desenler eklendi. Şifre göster/gizle ikonu, stilize checkbox, ve başlangıçta siber temalı boot-up animasyonu yapan yükleme ekranı entegre edildi.
6. **Live Activity Monitor Akış Yönü:** En yeni log en üstte olacak şekilde tersine çevrildi.
7. **Unit Test Kapsamı Artırma:** `config.py`, `orchestrator.py` ve `services/base.py` modülleri için temel testler eklendi.
8. **.gitignore Güncelleme:** `.env`, `*.db`, `node_modules/`, `dist/` dosyaları eklendi ve git cache'den temizlendi.
9. **Hatalı Import Düzeltme:** `orchestrator.py` içindeki `net_tuner` yolu düzeltildi.
10. **HONEYPOT_SECRET_KEY:** Yeni anahtar üretildi ve `.env` ile compose dosyalarına eklendi.
11. **Eksik Bağımlılık:** `aiosqlite` paketi `requirements.txt`'ye eklendi.
12. **Deprecated datetime.utcnow:** `models.py` içindeki kullanımlar `datetime.now(timezone.utc)` olarak güncellendi.
13. **Hardcoded Kimlik Bilgileri:** `docker-compose.lan.yml` dosyasındaki bilgiler dinamik `.env` referanslarına alındı.
14. **login.html Tema Uyumsuzluğu:** Login sayfasındaki tema script'i ana sayfayla uyumlu hale getirildi.
15. **Dockerfile Healthcheck:** Sağlık kontrolü Dockerfile'dan kaldırıldı.
16. **Dockerfile Eksik Portlar:** FTP, SSH, MSSQL vb. eksik honeypot servis portları EXPOSE satırına eklendi.
17. **Dead Code Silme:** Kullanılmayan `AppRouter.js` dosyası silindi.
18. **main.js Temizlik:** Kullanılmayan React değişkenleri kaldırıldı.
19. **event_logger.py Init Güvenliği:** `DBEventLogger` sınıfında lazy initialization yapısına geçildi.
20. **Honeypot DB Temizliği:** `logs/honeypot.db` git repo'sundan başarıyla kaldırıldı.
21. **Frontend Split:** `frontend/src/app-react.js` (3037 satır) başarıyla ES bileşenlerine bölündü ve silindi.
22. **Backend Router Ayrışımı:** `web/server.py` modüler handler'lara bölündü (655 satıra düştü).
23. **MITRE Panel Alert & Attacker IP Senkronizasyonu:** `Analyze.js`'deki React closure/timing bug'ı düzeltildi.
24. **setup.sh & start-lan.sh Macvlan .env Hatası:** `start-lan.sh` içindeki `REPO_ROOT` değişkeninin yanlışlığı giderilip REPO_ROOT iki üst dizine yönlendirildi.
25. **SIEM / aiohttp Bağımlılık ve 502 Hatası Düzeltildi:** `aiohttp` bağımlılığı `requirements.txt` dosyasına eklendi.
26. **Bildirim Çanı Konumlandırması Düzeltildi:** `NotificationBell` Portal altyapısına geçirildi, butonu `38px`'e düşürülerek genel hizalama sağlandı.
27. **Kritik: CSRF Token Tek Kullanımlık Yapıldı:** CSRF token her POST isteğinde taze çekilip veritabanında doğrulandıktan hemen sonra listeden silinerek tek kullanımlık hale getirildi.
28. **Kritik: `_save_users` Race Condition Çözüldü:** Tüm kullanıcıları sil-yaz yerine, veritabanı ile RAM'i senkronize eden insert/update/delete mantığına geçildi.
29. **Güvenlik: SIEM Endpoint'lerinde Admin Yetki Kontrolü Eklendi:** `/api/settings/siem` ve `/api/settings/siem/test` endpoint'lerine `_is_admin` kontrolü eklendi.
30. **Güvenlik: Hardcoded API Anahtarları Kaldırıldı:** AbuseIPDB ve GreyNoise API anahtarları temizlendi.
31. **Güvenlik: Çerezler için Secure Flag Desteği Eklendi:** Session çerezine HTTPS durumuna göre otomatik `Secure` bayrağı eklendi.
32. **Performans/Güvenlik: resolve_mac için ARP Caching Eklendi:** Bellek tabanlı 1 saatlik IP-MAC önbellekleme mekanizması kuruldu.
33. **Güvenlik: read_recent_events details Alanı Filtrelendi:** details nesnesinin içerisindeki kritik alanların manipülasyonunu önlemek için filtreleme eklendi.
34. **Ölü Kod: common.js Temizliği:** Kullanılmayan `setText`, `applyRoleVisibility` ve `ensureAuthenticated` fonksiyonları temizlendi.
35. **Ölü Kod: test_cpu.py Dosyası Silindi:** Geçici test betiği diskten temizlendi.
36. **Boş Mantık Düzeltmeleri:** `siem_forwarder.py` HTTP URL mantığı ve `orchestrator.py` boş start_service pass dalları temizlendi.
37. **Boş Mantık: defense.py Sayaç Sıfırlama:** IP banlandığında sayaçlar temizlenerek mükerrer DB yazmalarının önüne geçildi.
38. **Kod Kalitesi İyileştirmeleri:** Dashboard imla hataları düzeltildi, `Live.js` user pill ve logout buton stilleri uyumlu hale getirildi.
39. **Matrix Tema Sistemi (Base Mode + Color Accents):** Koyu/Açık tema ve 6 farklı renk akranı matris altyapısı Settings->Appearance sekmesine entegre edildi.
40. **SIEM Entegrasyonu: Çoklu Hedef Desteği:** Birden fazla SIEM hedefini asenkron olarak UDP, TCP ve HTTP üzerinden besleyecek yapı kuruldu.
41. **CSP Güvenliği & globe.gl Entegrasyonu:** globe.gl kütüphanesi ve theme-loader inline script'leri yerelleştirilerek CSP kuralları sağlandı.
42. **ResourceGauge CSS Entegrasyonu:** Gauge stilleri `styles.css` dosyasına taşınarak inline stil kalıntıları silindi.
43. **CPU Ölçümü Caching Mekanizması:** İsteklerdeki 200ms gecikmeyi engellemek için CPU kullanımı 5 saniyelik arka plan göreviyle önbelleklendi.
44. **MutationObserver Debounce:** Core.js bildirim portalı gözlemcisi 100ms debounce edilerek render yükü azaltıldı.
45. **read_recent_events DB Sorgusu Caching:** Analitik yükünü azaltmak için bu sorgu 3 saniye TTL ile önbelleklendi.
46. **SIEM TCP Soket Bağlantı Kalıcılığı:** Her olayda soket aç-kapa yerine tekil ve kalıcı TCP soketi kuruldu.
47. **Sunucu Tabanlı Sayfalama (Server-side Pagination):** Logs sayfası 50.000+ logda çökmeleri önlemek için SQL tabanlı `limit` ve `offset` sayfalamasına geçirildi.
48. **Gelişmiş Arama ve Regex Desteği:** Logs arama alanı regex desteği ve kolona özel arama seçenekleriyle genişletildi.
49. **Şüpheli Olay Filtresi (Exclude System Logs):** Logs sayfasına sistem loglarını gizleme seçeneği eklendi.
50. **Threat Intel Test Düzeltmeleri:** SQLAlchemy bağlantı havuzunun çökme hatası NullPool ve tekil event loop ile çözüldü.
51. **Go Backend Geliştirme (Tüm Decoy Servisleri & Web API):** 14 Decoy servisin tamamı Go dilinde asenkron logger, otomatik banlama, firewall kancaları ve go-chi API sunucusu ile sıfırdan yazılarak entegre edildi.
52. **Go Backend Kod Denetimi:** Go 1.25 yükseltmesi, config.yaml mount yolu, logger drain mekanizması, regex arama düzeltmeleri ve base.go timeout iyileştirmeleri yapıldı.
53. **Go Servis Yöneticisi (Orchestrator) & Yönetim API Entegrasyonu:** Servisleri veritabanı durumuna göre dynamically yöneten asenkron Orchestrator syncLoop altyapısı yazıldı, tüm API handler'ları bağlandı.
54. **Go Backend Kritik Hata Düzeltmeleri (Faz 1):** `system_settings` kolonunun TEXT yapılması, IPv6 JoinHostPort düzeltmesi, 24 saatlik session expiry ve cleanup goroutine'i, SIEM double json marshal optimizasyonu ve iptables banlama IPv6/MAC ayrım tespiti tamamlandı.
55. **Go Backend Mimari ve Performans İyileştirmeleri (Faz 2):** `/api/overview` analitik sorguları için 10s stats caching yapıldı, `formatEventMap` helper'ı yazıldı, dynamic CPU/Disk hesapları Linux sisteminden çekildi ve cache overflow/reset mantıkları kuruldu.
56. **Go Backend Yapısal ve Zaman Aşımı İyileştirmeleri (Faz 3):** Varsayılan admin şifresinin başlangıçta hashlenerek DB'ye yazılması, SSE için `WriteTimeout: 0` ve Nginx `proxy_read_timeout 86400s` tanımlanması, syncLoop bağımsız timeout context'i, template ismi prefix tespiti ve dynamic looping service factory mapping entegrasyonu tamamlandı.

---

### 🔍 Go Backend — Kapsamlı Kod Denetim Raporu (Tarihsel Referans)

Faz 1, Faz 2 ve Faz 3 öncesinde `go-backend/` kod tabanı üzerinde yapılan analizlerde tespit edilen hatalar ve uygulanan düzeltmelerin arşividir.

#### 1. `system_settings.setting_value` sütunu `VARCHAR(255)` — Veri Kaybı Riski (Kritik)
- **Dosya:** [database.go](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/database/database.go#L93-L97)
- **Sorun:** `orchestrator_state` JSON verisi (profil adı + 12+ servis override'ı + running services listesi) kolayca 255 karakteri aşar. PostgreSQL bu değeri **sessizce keser** ve JSON parse hatası oluşur → orchestrator state sıfırlanır. Aynı sorun `siem_config` için de geçerli.
- **Çözüm:** `setting_value VARCHAR(255)` → `setting_value TEXT` olarak değiştirildi.

#### 2. IPv6 Adresleri İçin `fmt.Sprintf("%s:%d")` Kullanımı — Bağlantı Hatası (Kritik)
- **Dosya:** [forwarder.go](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/siem/forwarder.go#L167-L184)
- **Sorun:** IPv6 literal adresleri `[::1]:514` formatında olmalı ama `fmt.Sprintf("%s:%d", host, port)` ile `::1:514` üretiliyordu → dial başarısız oluyordu.
- **Çözüm:** `net.JoinHostPort` fonksiyonuna geçilerek otomatik köşeli parantez eklenmesi sağlandı.

#### 3. Session Expiry Mekanizması Yok — Güvenlik Açığı (Kritik)
- **Dosya:** [database.go](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/database/database.go#L200-L208)
- **Sorun:** `sessions` tablosunda eski session'lar temizlenmiyordu ve sunucu tarafında oturumlar sonsuza kadar geçerli kalıyordu.
- **Çözüm:** Oturumlara 24 saatlik TTL sınırı konuldu ve saatte bir eski oturumları temizleyen asenkron cleanup goroutine'i server.go'ya entegre edildi.

#### 4. SIEM Forwarder'da Double JSON Marshal — Gereksiz Bellek Kullanımı (Kritik)
- **Dosya:** [forwarder.go](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/siem/forwarder.go#L155-L220)
- **Sorun:** HTTP protokolü branşında event nesnesi gereksiz yere iki kez marshal ediliyordu.
- **Çözüm:** İlk üretilen `payloadBytes` (satır sonu ayıklanarak) doğrudan kullanıldı, mükerrer marshal çağrısı kaldırıldı.

#### 5. `ApplyFirewallRule` IPv6 Hatalı Algılama (Kritik)
- **Dosya:** [net_tuner.go](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/system/net_tuner.go#L168-L173)
- **Sorun:** İki nokta `:` karakteri içeren IPv6 adresleri yanlışlıkla MAC adresi kuralı (`--mac-source`) olarak iptables'a eklenip firewall'u bozuyordu.
- **Çözüm:** IP adreslerinin tespiti için `net.ParseIP` ön kontrolü eklendi.

#### 6. `HandleOverview` Dev Fonksiyon — 220 Satır, 8 DB Sorgusu (Önemli)
- **Dosya:** [overview_handlers.go](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/overview_handlers.go#L372-L589)
- **Sorun:** Dashboard açılışında 8 ayrı veritabanı sorgusu, GeoIP batch lookup ve ARP resolution tekil handler içinde senkron çalışıyor ve yüksek latency oluşturuyordu.
- **Çözüm:** Parametresiz landing istekleri için 10 saniye süreyle stats ve geo verileri RAM üzerinde önbelleklendi (statsCache).

#### 7. `HandleEvents` ve `HandleOverview` Arasında Büyük Kod Tekrarı (Önemli)
- **Dosyalar:** [overview_handlers.go L261-L327](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/overview_handlers.go#L261-L327) ve [overview_handlers.go L408-L441](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/overview_handlers.go#L408-L441)
- **Sorun:** Event satırlarını scan edip JSON map oluşturan kod bloğu birebir kopyalanmıştı.
- **Çözüm:** scanEventRow/formatEventMap fonksiyonu altında ortak bir helper yazılıp iki uç noktaya da entegre edildi.

#### 8. `ServiceStatus` Struct'ı İki Kez Tanımlanmış (Kullanılmayan Versiyon) (Önemli)
- **Dosyalar:** [overview_handlers.go L23-L31](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/overview_handlers.go#L23-L31) ve [orchestrator.go L425-L433](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/services/orchestrator.go#L425-L433)
- **Sorun:** `web.ServiceStatus` tanımlıydı ama hiçbir yerde kullanılmıyordu (gerçekte `services.WebServiceStatus` kullanılıyor).
- **Çözüm:** Ölü kod tabanından temizlendi.

#### 10. `HandleGetSettings` — CPU ve Disk Değerleri Hardcoded (Önemli)
- **Dosya:** [management_handlers.go L606-L618](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/management_handlers.go#L606-L618)
- **Sorun:** CPU %1.5 ve Disk %15.2 olarak tamamen statik dönüyordu.
- **Çözüm:** Linux sisteminden `/proc/loadavg` ve `df -k` kullanılarak gerçek sistem metrikleri okundu ve API'ye bağlandı.

#### 11. GeoIP Cache Sınırsız Büyüme (Önemli)
- **Dosya:** [utils.go L297](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/utils.go#L297)
- **Sorun:** `geoCache` 5000 entry'ye kadar büyüyordu ama temizlenmediği için bellek sızıntısına neden oluyordu.
- **Çözüm:** Cache limit aşıldığında map sıfırlanarak temizlenme mantığı entegre edildi.

#### 12. ARP Cache Thread Safety Sorunu (Önemli)
- **Dosya:** [utils.go L88-L137](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/utils.go#L88-L137)
- **Sorun:** `loadArpTable` çağrıldığında eski stale ARP kayıtları temizlenmiyor ve birikiyordu.
- **Çözüm:** loadArpTable tetiklendiğinde map sıfırlanarak stale ağ cihazlarının birikmesi engellendi.

#### 13. Orchestrator.NewOrchestrator() — Hardcoded Servis Mapping (Orta Seviye)
- **Dosya:** [orchestrator.go](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/services/orchestrator.go#L62-L123)
- **Sorun:** Her servis tipi için ayrı `if c, ok := cfg.Services["xxx"]; ok { ... }` bloğu var. Yeni servis eklemek için bu fonksiyona elle ekleme yapmak gerekiyor.
- **Çözüm:** Service factory/registry veya dynamic loop mapping yapısına geçilerek hardcoded eşleşmeler kaldırıldı (serviceFactories registry map + dynamic looping yapısına geçildi).

#### 14. `GetServicesStatus` — Template Name Heuristic (Orta Seviye)
- **Dosya:** [orchestrator.go L460-L469](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/services/orchestrator.go#L460-L469)
- **Sorun:** Template adı servis adından prefix parsing ile çıkarılıyordu (`name[:5] == "http_"` gibi). Kırılgan bir yapıydı.
- **Çözüm:** `strings.HasPrefix` kullanan dinamik bir prefix eşleşme döngüsü yazıldı.

#### 15. Orchestrator `syncLoop` Kendi Context'ini Kullanıyor (Orta Seviye)
- **Dosya:** [orchestrator.go L369](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/services/orchestrator.go#L369)
- **Sorun:** `o.getDBState(o.ctx)` — orchestrator stop edilirken bu context cancel oluyor ve DB sorgusu loglarda context cancel hatası fırlatıyordu.
- **Çözüm:** DB sorguları için 3 saniye zaman aşımı olan bağımsız context atandı.

#### 16. `HandleLogin` — Config'den Gelen Şifre Her Seferinde Hash'leniyor (Orta Seviye)
- **Dosya:** [auth_handlers.go L89-L91](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/auth_handlers.go#L89-L91)
- **Sorun:** Varsayılan admin şifresi DB'ye kaydedilmemişti, her girişte hashlenip doğrulanıyordu (timing attack riski ve CPU yükü).
- **Çözüm:** Sunucu başlangıcında (init) varsayılan kullanıcı DB'de yoksa bir kez hash'lenip kaydedildi.

#### 19. `generateToken` Fonksiyonu İki Kez Tanımlı (Düşük Seviye)
- **Dosyalar:** [auth_handlers.go L29-L35](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/auth_handlers.go#L29-L35)
- **Sorun:** Hem `auth_handlers` hem `overview_handlers` ayrı ayrı generateToken barındırıyordu.
- **Çözüm:** Fonksiyon `utils.go` dosyasına taşınarak tekilleştirildi.

#### 20. Nginx Config'de SSE Location Block Sırası Önemli (Düşük Seviye)
- **Dosya:** [nginx.conf L19-L37](file:///c:/Users/BERN/honeypot-orchestrator/frontend/nginx.conf#L19-L37)
- **Sorun:** `/api/alerts/stream` Nginx proxy bloğunda `proxy_read_timeout` eksikti, sessiz geçen 60s sonunda Nginx akışı koparıyordu.
- **Çözüm:** `proxy_read_timeout 86400s` ve `proxy_send_timeout 86400s` eklendi.

#### 21. `WriteTimeout: 15s` SSE Stream'i Kesiyor Olabilir (Düşük Seviye)
- **Dosya:** [server.go L184](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/server.go#L184)
- **Sorun:** Go HTTP sunucusunun default WriteTimeout (15s) değeri uzun SSE akışlarının yarıda kesilmesine yol açıyordu.
- **Çözüm:** Sunucu ayarlarında `WriteTimeout: 0` (sınırsız) yapıldı.

#### 22. `CSRF Token` Tek Kullanımlık — İlk POST'tan Sonra Yeniden Alınmalı (Düşük Seviye)
- **Dosya:** [server.go L77-L81](file:///c:/Users/BERN/honeypot-orchestrator/go-backend/web/server.go#L77-L81)
- **Sorun:** CSRF token silinme mantığı ve frontend senkronizasyonu.
- **Çözüm:** Backend normal davranışı doğrulandı, frontend tarafının her POST öncesi token'ı tazelediği doğrulandı.

#### 3. Go Backend Dizin Yapısı Reorganizasyonu (Önemli)
- **Sorun:** Standartlara uygun (`cmd/` ve `internal/`) modüler bir dizin yapısına geçiş ihtiyacı.
- **Çözüm:** Eski Python `backend/` dizini temizlendi, `go-backend/` dizini `backend/` yapıldı. config, database, logger, profiles, siem, system, web paketleri `internal/` altına, main.go `cmd/honeypot-daemon/` altına taşındı. Decoy servisler `tcp/` ve `udp/` olarak ayrılıp dairesel bağımlılığı (import cycle) önleyen anonymous registry deseni ile yapılandırıldı.

#### 9. PortNameHost() — 14 Boilerplate Metod (Düşük Seviye)
- **Sorun:** Her servis tipi için ayrı delegasyon metotları bulunmaktaydı.
- **Çözüm:** `orchestrator.go` üzerindeki tekrarlı metotlar kaldırıldı, decoy struct'larının içerisine delege edilerek izole edildi.

#### 17. Python backend/ Dizini Temizliği (Önemli)
- **Sorun:** Eski Python dosyaları dizinde kafa karışıklığı yaratıyordu.
- **Çözüm:** Python dosyaları ve eski dizin tamamen silindi.

#### 18. Build Artifact Repo'dan Silinmesi — honeypot-daemon.exe (Düşük Seviye)
- **Sorun:** Derlenmiş binary deposu kirletiyordu.
- **Çözüm:** Fiziksel binary git/dizin geçmişinden tamamen silindi ve `.gitignore` ile dışlandı.

#### 57. Kapsamlı Kod Denetimi ve Analiz Raporu Hazırlanması
- **Sorun:** Yeni Go mimarisi ve React frontend kod tabanı üzerindeki tüm olası mantıksal hataların, güvenlik açıklarının, ölü kodların ve dizin yapısı eksikliklerinin detaylı analiz edilmesi gerekiyordu.
- **Çözüm:** Tüm kodlar baştan sona denetlendi. Yeni Go yapısındaki kritik açıklar (DNS UDP eksikliği, SMB/NetBIOS sınırsız bellek tahsisi DoS riski, AlertStreamer goroutine sızıntısı vb.) tespit edildi. [code_audit_report.md](file:///c:/Users/BERN/.gemini/antigravity-ide/brain/e39bd832-d5ec-4016-b5f5-1677a695bf48/code_audit_report.md) güncellenerek detaylı bir şekilde raporlandı ve yapılacaklar listesine eklendi.

