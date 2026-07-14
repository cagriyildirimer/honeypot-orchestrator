# Honeypot Orchestrator - Memory & Next Steps

## 📋 To-Do & Next Steps

## 🏗️ Proje Mimari ve Dosya Yapısı (Mevcut Durum)

```
honeypot-orchestrator/
├── docker-compose.yml                 # Standart Go + Postgres + React Çoklu-Mikroservis Konfigürasyonu
├── docker-compose.lan.yml             # LAN Modu için Macvlan Destekli Go + React Konfigürasyonu
├── setup.sh                           # İnteraktif IP, şifreleme ve veritabanı ayarlarını yapan kurulum betiği
├── .env.example                       # Çevre değişkenleri şablon dosyası
├── config.yaml                        # API yetkilendirme, veritabanı ve SIEM hedeflerini barındıran konfigürasyon
├── README.md                          # Proje kurulum ve kullanım kılavuzu
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
│   │   │   ├── tcp/                   # TCP decoy servisleri dizini
│   │   │   │   ├── ftp.go             # FTP (ProFTPD / MSFTP taklidi) tuzak servisi
│   │   │   │   ├── http.go            # HTTP (Nginx / IIS taklidi) tuzak servisi
│   │   │   │   ├── ldap.go            # LDAP dizin servisi taklidi
│   │   │   │   ├── ldaps.go           # Güvenli LDAPS dizin servisi taklidi
│   │   │   │   ├── mssql.go           # MS SQL Server veritabanı taklidi
│   │   │   │   ├── netbios.go         # NetBIOS Session Service taklidi
│   │   │   │   ├── rdp.go             # RDP (Uzak Masaüstü) protokol taklidi
│   │   │   │   ├── rpc.go             # MSRPC (Remote Procedure Call) taklidi
│   │   │   │   ├── smb.go             # SMBv2/v3 dosya paylaşım protokol taklidi
│   │   │   │   ├── ssh.go             # SSH (OpenSSH Windows/Linux taklidi) tuzak servisi
│   │   │   │   └── telnet.go          # Telnet terminal servisi taklidi
│   │   │   └── udp/                   # UDP decoy servisleri dizini
│   │   │       ├── dns.go             # DNS ad çözümleme tuzak servisi
│   │   │       ├── llmnr.go           # LLMNR multicast ad çözümleme taklidi
│   │   │       └── nbtnns.go          # NetBIOS Name Service UDP taklidi
│   │   ├── siem/                      # UDP/TCP/HTTP SIEM log yönlendirici motoru
│   │   ├── system/                    # iptables firewall yönetimi ve sysctl parametre güncelleyici
│   │   └── web/                       # go-chi router, CSRF/Auth middleware'ler ve JSON API uç noktaları
│   ├── scripts/
│   │   └── start-lan.sh               # LAN modunda decoy ağ yapılandırma ve firewall başlatma betiği
│   ├── tests/
│   │   └── test_threat_intel.py       # Tehdit istihbaratı test betiği
│   ├── Dockerfile                     # Derleme ve çalıştırma Dockerfile'ı
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

## 🗄️ Veritabanı Tablo Yapıları (PostgreSQL)

Honeypot verileri ve yönetim yapılandırması PostgreSQL veritabanında saklanır. Tabloların yapısı ve kullanım amaçları aşağıda listelenmiştir:

1.  **`events` (Olay Günlükleri):** Saldırganların decoy servislerine yaptığı tüm erişimleri saklar.
    *   `id` (SERIAL PRIMARY KEY): Benzersiz olay kimliği.
    *   `timestamp` (TIMESTAMPTZ, Default NOW()): Olayın gerçekleştiği tarih ve saat.
    *   `service` (VARCHAR(255)): Olayı tetikleyen servis (örn: `ssh_linux`, `smb_windows`).
    *   `event_type` (VARCHAR(255)): Olay tipi (örn: `connection_attempt`, `login_success`, `file_access`).
    *   `src_ip` (VARCHAR(255)): Saldırganın IP adresi.
    *   `src_port` (INTEGER): Saldırganın kaynak portu.
    *   `summary` (TEXT): Olayın kısa özeti.
    *   `details` (JSONB): Protokole özel detaylar (örn: girilen şifreler, çalıştırılan SQL sorguları).

2.  **`users` (Yöneticiler):** Yönetim paneline giriş yapabilecek yetkili kullanıcıları tutar.
    *   `id` (SERIAL PRIMARY KEY)
    *   `username` (VARCHAR(255) UNIQUE)
    *   `password_hash` (VARCHAR(255)): bcrypt ile hash'lenmiş şifre.
    *   `role` (VARCHAR(255), Default 'viewer'): Kullanıcı rolü (`admin` / `viewer`).

3.  **`sessions` (Oturumlar):** Giriş yapan yöneticilerin aktif tarayıcı oturumlarını takip eder.
    *   `session_id` (VARCHAR(255) PRIMARY KEY): Benzersiz session token'ı.
    *   `username` (VARCHAR(255))
    *   `role` (VARCHAR(255))
    *   `created_at` (TIMESTAMPTZ, Default NOW()): Oturum başlangıç zamanı (24 saatlik TTL süresi vardır).

4.  **`whitelist` (Beyaz Liste):** Otomatik engelleme (IP ban) mekanizmasından hariç tutulan IP adresleri.
    *   `id` (SERIAL PRIMARY KEY)
    *   `ip` (VARCHAR(255) UNIQUE): Güvenilen IP adresi.
    *   `description` (VARCHAR(255)): Ek açıklama.
    *   `timestamp` (TIMESTAMPTZ, Default NOW())

5.  **`blacklist` (Kara Liste):** Saldırı girişimleri sonucu otomatik veya manuel olarak engellenen IP adresleri.
    *   `id` (SERIAL PRIMARY KEY)
    *   `ip` (VARCHAR(255) UNIQUE): Engellenen IP adresi.
    *   `description` (VARCHAR(255)): Engelleme nedeni.
    *   `timestamp` (TIMESTAMPTZ, Default NOW())

6.  **`threat_intel_cache` (Tehdit İstihbaratı Önbelleği):** AbuseIPDB ve GreyNoise üzerinden sorgulanan IP'lerin itibar verileri.
    *   `ip` (VARCHAR(255) PRIMARY KEY)
    *   `data` (JSONB): İstihbarat servislerinden gelen detaylı JSON yanıtı.
    *   `updated_at` (TIMESTAMPTZ, Default NOW()): Önbelleğin son güncellenme tarihi.

7.  **`system_settings` (Sistem Ayarları):** SIEM yapılandırması ve orkestratörün profil durumu.
    *   `setting_key` (VARCHAR(255) PRIMARY KEY): Ayar anahtarı (örn: `siem_config`, `orchestrator_state`).
    *   `setting_value` (TEXT): Ayarın değeri (büyük JSON yapılandırmalarını saklayabilmek için TEXT tipindedir).
    *   `updated_at` (TIMESTAMPTZ, Default NOW())

---

## 📡 SIEM Entegrasyon Seçenekleri ve Protokolleri

Sistemde üretilen kritik alarmlar (`login_success`, `credential_attempt`, `ssh_command`, `sql_query` vb.) gerçek zamanlı olarak dış güvenlik izleme sistemlerine (SIEM) aktarılabilir.

*   **Desteklenen Aktarım Protokolleri:**
    1.  **Syslog (UDP):** Standart syslog sunucularına RFC 5424 formatında hızlı log aktarımı.
    2.  **Syslog (TCP):** Bağlantı kalıcılığı ve hata denetimli TCP akışı (3 kez backoff retry destekli).
    3.  **HTTP Webhook:** Splunk HEC (HTTP Event Collector), Slack webhook kanalları veya genel JSON Webhook hedeflerine HTTP POST üzerinden JSON payload gönderimi.
*   **Filtreleme Kapsamları (Scopes):**
    *   `all`: Decoy servislerindeki en ufak TCP/UDP bağlantı denemesi dahil tüm olayları yönlendirir.
    *   `alerts`: Sadece saldırganın başarılı girişleri, terminal komutları, SQL enjeksiyon sorguları gibi yüksek önem dereceli (critical) olayları yönlendirir.

---

## 🛡️ Aktif Savunma ve Otomatik Engelleme (Active Defense)

*   **Otomatik Ban Mekanizması:** Saldırgan decoy servislerine (örn: SSH veya FTP) belirli bir eşikten fazla hatalı istek gönderdiğinde, IP adresi tespit edilerek otomatik olarak `blacklist` tablosuna yazılır.
*   **Firewall Entegrasyonu:** `system/net_tuner.go` modülü, `blacklist` tablosundaki IP'leri Linux kernel seviyesinde engellemek için `iptables` kuralları oluşturur:
    ```bash
    iptables -A HONEYPOT_INPUT -s <attacker_ip> -j DROP
    ```
*   **IP Beyaz Liste Koruması:** `whitelist` tablosundaki IP'ler bu engelleme adımlarından tamamen muaf tutulur.


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
57. **Kapsamlı Kod Denetimi Raporu Hazırlanması:** Yeni Go mimarisi ve React frontend kod tabanı üzerindeki tüm olası mantıksal hatalar, güvenlik açıkları ve dizin yapısı eksiklikleri denetlendi, `code_audit_report.md` dosyasına raporlandı ve yapılacaklar listesine eklendi.
58. **MITRE ATT&CK Desteği ve `/api/analyze` Uç Noktası:** Analiz sayfası için MITRE ATT&CK taktik/teknik olay eşleme logic'i, saatlik timeline ve ülke bazlı kırılım analizi yapan Go backend handler'ı yazıldı ve router'a bağlandı.
59. **3D Dünya Haritası Düzeltmeleri ve Çevrimdışı/LAN Uyumlaştırması:** Harita doku dosyaları yerel `/vendor/` dizinine indirilip `Core.js` üzerinden yerel yollarla çağrılarak uygulama çevrimdışı çalışmaya hazır hale getirildi. `Dashboard.js`'deki veri okuma kaynağı `stats.geo_markers` olarak düzeltildi.
60. **Bildirim Kalıcılığı ve SSE Alarmlarının İngilizceye Çevrilmesi:** `NotificationBell` state verileri `localStorage` ile senkronize edilerek tarayıcıda kalıcı olmaları sağlandı. SSE yayıncısındaki tüm bildirim formatları ve şablonları tamamen İngilizceye çevrildi.
61. **Tehdit İstihbaratı (TI Worker) Çoklu Konteyner İzolasyonu:** Tehdit İstihbaratı (TI) arka plan işleyicisi (worker) ana backend'den izole edilerek standart ve LAN compose dosyalarında `honeypot-ti` isimli bağımsız bir konteyner servisine taşındı.
62. **Saldırgan Zaman Tüneli ve Coğrafi Aktivite Panel Entegrasyonu:** `buildFilterSQL` fonksiyonuna `src_ip` sorgu parametresi desteği eklenerek timeline sorguları düzeltildi. Haritanın soluna coğrafi konum bilgileri ve en çok hedef alınan servis bilgilerini listeleyen cam efektli yüzer panel yerleştirildi.
63. **DNS UDP Desteği Doğrulaması:** DNS decoy servisinin `BaseUDPService` yapısını kullandığı ve `1053/udp` portu üzerinden çalıştığı, compose dosyalarında UDP eşleşmelerinin doğru yapıldığı doğrulandı.
64. **SMB ve NetBIOS OOM/DoS Sınırlandırması Doğrulaması:** `smb.go` ve `netbios.go` dosyalarında gelen paket payload uzunluklarının maksimum 64KB ile sınırlandırıldığı ve OOM zafiyetlerinin engellenmiş olduğu doğrulandı.
65. **AlertStreamer Context Sızıntısı Giderim Doğrulaması:** AlertStreamer SSE yayıncısının `context.Background()` yerine sunucu yaşam döngüsüne bağlı root sinyal context'i ile başlatıldığı ve kaynak sızıntılarının engellendiği doğrulandı.
66. **SIEM TCP Reconnect ve Kademeli Bekleme (Backoff) Mekanizması:** `forwarder.go` içerisinde TCP gönderim yapısı revize edilerek soket hatalarında 3 kez deneme (attempts) ve kademeli bekleme (backoff - 1s, 2s) retry mekanizması entegre edildi.
67. **Go Web Filtreli İstatistik Hatası Düzeltildi:** `HandleOverview` altındaki `by_service` ve `by_type` istatistik sorgularına aktif filtreleme parametreleri (`whereClause` ve `args`) uygulanarak panel grafikleriyle log listesi arasındaki tutarsızlık giderildi.
68. **SMB Decoy Read DataOffset Hizalama Düzeltildi:** `buildSmb2ReadResponse` fonksiyonundaki `DataOffset` değeri 72'den 80'e güncellenerek SMB2 başlık (64) ve metadata (16) uyumluluğu sağlandı ve katı SMB istemcilerinin bağlantı koparmasının önüne geçildi.
69. **SIEM TCP Bağlantı Sızıntısı Giderildi:** Concurrency (eşzamanlı olay aktarımı) durumunda birden fazla soket açılmasını engellemek amacıyla `forwarder.go` altında mutex kilit kontrolü ile Dial sonrası mükerrer soketleri kapatıp mevcut soketi yeniden kullanan güvenli bağlantı havuzu yapısı kuruldu.
70. **SIEM HTTP Webhook Port Ezme Hatası Çözüldü:** Webhook veya HEC gibi portsuz standart absolute URL'lerin sonuna `:514` (varsayılan syslog portu) eklenmesi sorunu giderildi. HTTP hedefleri için port bilgisi artık sadece kullanıcı tarafından elle girildiğinde (`port > 0` ve `!= 80/443`) URL'e dahil ediliyor.
71. **SSE Bildirim Fırtınası (Toast Storm) Engellendi:** Arayüz kapalıyken arka planda biriken olayların, arayüz ilk açıldığında toplu halde tarayıcıya yığılmasını önlemek amacıyla `alert_streamer.go` üzerinde istemci yokken `lastID` değerini `-1`'e çekerek veritabanı sorgu yükünü ve "toast storm" olayını engelleyen geçiş tabanlı önbellek yapısı kuruldu.
72. **Çoklu Konteyner SIEM Senkronizasyonu ve Olay Kapsamı Genişletildi:** LAN modunda (ayrı konteynerler) Web UI'dan güncellenen SIEM yapılandırmasının Decoy konteynerine yansıması için `forwarder.go` içerisine 10 saniyede bir çalışan dinamik veritabanı senkronizasyon döngüsü (`startSyncLoop`) eklendi. Ayrıca `"alerts"` kapsamı genişletilerek başarılı girişler (`login_success`), HTTP kimlik denemeleri (`credential_attempt`), SSH komutları (`ssh_command`) ve SQL sorguları (`sql_query`) kritik olay listesine dahil edildi.
73. **Web API Konteynerinde Decoy Servislerin Başlatılması Engellendi:** LAN/Çoklu Konteyner modunda Web API konteyneri (`honeypot-web-lan`) üzerinde profil değiştirildiğinde veya servis tetiklendiğinde `applyState` çağrısının decoy servislerini ve iptables kurallarını bu konteynerde gereksiz yere çalıştırması engellendi (`HONEYPOT_DECOYS_ENABLED == "false"` kontrolü ile).
74. **İlk Kurulum Varsayılan Profili 'empty' Yapıldı:** Veritabanının sıfırdan kurulduğu ilk çalışma anında sistemin varsayılan olarak `"empty"` (boş) profille başlaması sağlandı.
75. **system_settings.setting_value Sütun Boyutu TEXT'e Dönüştürüldü (Eski 1):** `orchestrator_state` ve `siem_config` JSON verilerinin 255 karakter sınırına takılıp kesilerek JSON parse hatası vermesini engellemek için kolon tipi TEXT yapıldı.
76. **IPv6 Adresleri İçin net.JoinHostPort Entegrasyonu (Eski 2):** SIEM göndericisinin IPv6 hedef adresleri köşeli parantezsiz yazıp hatalı Dial yapması `net.JoinHostPort` kullanılarak çözüldü.
77. **Oturum Süre Sınırı ve Cleanup Goroutine'i (Eski 3):** `sessions` tablosundaki oturumların sonsuza kadar geçerli kalmaması için 24 saatlik TTL sınırı ve saatlik temizleme döngüsü eklendi.
78. **SIEM HTTP Forwarder Double Marshal Giderildi (Eski 4):** HTTP post işlemi sırasında event verisinin iki kez serialize edilerek gereksiz işlemci ve bellek yükü oluşturması engellendi.
79. **ApplyFirewallRule IPv6/MAC Algılaması Düzeltildi (Eski 5):** İki nokta içeren IPv6 adreslerinin iptables kuralında hatalı bir şekilde MAC adresi olarak parse edilerek firewall kurallarını bozması `net.ParseIP` kontrolü ile giderildi.
80. **HandleOverview Stats Önbelleklemesi (Eski 6):** Dashboard açılışında atılan 8 ayrı DB sorgusu, GeoIP lookup ve ARP sorgularının latency oluşturmasını engellemek için landing isteklerine 10 saniyelik `statsCache` RAM önbelleği uygulandı.
81. **Scan ve Format Event Kod Tekrarı Temizlendi (Eski 7):** `HandleEvents` ve `HandleOverview` altında mükerrer olarak yazılmış olan veritabanı satır okuma ve biçimlendirme kodları `formatEventMap` altında birleştirildi.
82. **Kullanılmayan web.ServiceStatus Tanımı Silindi (Eski 8):** Hiçbir yerde kullanılmayan mükerrer durum yapısı kod tabanından temizlendi.
83. **Arayüz Ayarlarında Gerçek CPU/Disk Metrikleri Bağlandı (Eski 10):** CPU için `/proc/loadavg`, disk için `df -k` komutları kullanılarak arayüzde statik gösterilen metrikler yerine gerçek Linux kaynak değerleri çekildi.
84. **GeoIP Önbelleği Sınırsız Büyüme Engeli (Eski 11):** `geoCache` haritasının bellekte sürekli büyüyerek sızıntı yapmaması için 5000 kaydı aşınca otomatik temizlenme mantığı eklendi.
85. **ARP Tablosu İş Parçacığı Güvenliği (Eski 12):** `loadArpTable` tetiklendiğinde eskiyen stale kayıtların birikmesini önlemek için map sıfırlanarak güncellenmesi sağlandı.
86. **Orchestrator Registry Fabrika Yapısına Geçildi (Eski 13):** Yeni tuzak servisler eklendikçe `NewOrchestrator`'a elle ekleme yapma gereksinimi, anonymous registry fabrikası ve dinamik loop yapısıyla ortadan kaldırıldı.
87. **GetServicesStatus Şablon Adı Parsing'i Dinamikleştirildi (Eski 14):** Servis adından katı string kesimleri yerine `strings.HasPrefix` kullanan dinamik şablon adı eşleştirme yapısına geçildi.
88. **syncLoop DB Sorgu Context'i İyileştirildi (Eski 15):** Sunucu kapanırken loglarda context iptal hataları oluşmaması için DB durum sorgularına bağımsız 3 saniyelik timeout context'i atandı.
89. **Yönetici Giriş Şifresi Pre-Hash Kaydı (Eski 16):** Her girişte varsayılan admin şifresinin tekrarlı hash'lenerek CPU yükü yaratması, başlangıçta kullanıcı yoksa bir kez hash'lenip DB'ye kaydedilmesi yöntemiyle çözüldü.
90. **generateToken utils.go Altında Tekilleştirildi (Eski 19):** İki farklı yerde ayrı ayrı tanımlanmış olan token üretim fonksiyonu `utils.go`'ya taşınarak ortaklaştırıldı.
91. **Nginx SSE proxy_read_timeout Ayarı (Eski 20):** SSE akışının 60 saniye sessizlikten sonra Nginx tarafından kapatılmasını önlemek için okuma ve yazma zaman aşımı limitleri 86400 saniyeye çıkarıldı.
92. **Go HTTP Server WriteTimeout Sınırsız Yapıldı (Eski 21):** Go sunucusunun 15 saniyelik varsayılan yazma zaman aşımının uzun ömürlü SSE bağlantısını koparmasını önlemek için `WriteTimeout: 0` (sınırsız) olarak ayarlandı.
93. **CSRF Tek Kullanımlık Token Güvenliği (Eski 22):** Replay saldırılarını engellemek amacıyla doğrulanmış CSRF token'ı eşleşmenin hemen ardından bellekten silinecek şekilde güncellendi.
94. **Go Backend Dizin Yapısı Reorganizasyonu:** Kod tabanı standart Go pratiklerine göre `cmd/` ve `internal/` modüler yapısına dönüştürülüp dairesel bağımlılıklar giderildi.
95. **Boilerplate PortNameHost Delege Metotları Kaldırıldı:** 14 farklı decoy sınıfında bulunan mükerrer metotlar `BaseTCPService` yapısına taşındı.
96. **Eski Python backend/ Dizin ve honeypot-daemon.exe Temizliği:** Eski kafa karıştırıcı Python dosyaları ile derlenmiş exe binary dosyası git ve fiziksel dizin geçmişinden kalıcı olarak temizlendi.
97. **Gelişmiş Etkileşimli Fake Shell (SSH & Telnet):** SSH ve Telnet servislerine login attempts takibi eklenerek 2. denemede başarılı giriş sağlandı. Saldırganların kabuk içinde `wget` veya `curl` ile sahte zararlı indirme akışları simüle edilerek dosyalar diskte yakalandı, SHA-256 özetleri çıkarılarak veritabanına `captured_payload` olarak kaydedildi ve bellek içi sanal dosya sistemi ile `ls`, `dir`, `cat` ve `type` komutları üzerinden saldırganın erişimine sunuldu.
98. **FTP Decoy & Dynamic Passive Mode STOR Capturing:** FTP decoy servisi genişletilerek `USER`, `PASS` (2. denemede başarı), `PWD`, `SYST`, `TYPE`, `LIST` komutları emüle edildi. Dinamik `PASV` passive mode TCP veri dinleyici port tahsisi entegre edilerek `STOR` ile yapılan tüm dosya yüklemeleri diskte yakalanıp Malware Analyzer ile tarandı ve kaydedildi.
99. **TCP Tarpit (Active Defense) Mekanizması:** Kara listedeki (banlanmış) saldırganların bağlantılarının doğrudan kesilmesi yerine `base.go` üzerinden TCP tarpit havuzuna alınarak 15 saniyelik okuma/yazma gecikmeleriyle scanner ve brute-force thread'leri kilitlendi ve yönetim panelinde alarmlandı.
100. **Ücretsiz Malware Analyzer Motoru (Local Regex + MalwareBazaar API):** Yakalanan dosyaların taranması için internet gerektirmeyen çevrimdışı regex imza tarayıcısı ve internet varken abuse.ch MalwareBazaar API üzerinden tamamen ücretsiz tehdit sorgulaması yapan çift katmanlı tarama motoru entegre edildi.
101. **Analyze.js Paneline Payloads ve Tarpit Tabları Entegre Edildi:** Yönetim paneli analiz sayfasına yakalanan tüm zararlı yazılımların SHA-256, boyut ve detaylarıyla izlenebildiği "Captured Payloads" sekmesi ile o an trap'te meşgul edilen saldırgan IP'lerinin ve istatistiklerinin gösterildiği "TCP Tarpit Activity" sekmesi entegre edildi.
102. **WinRM (Port 5985) HTTP Emülasyonu ve Windows Profiline Entegrasyonu:** Windows Remote Management (WinRM) servisini taklit edecek bir HTTP sunucu simülatörü yazıldı. /wsman uç noktasına gelen SOAP Identify isteklerine "Microsoft Corporation" imzalı XML yanıtı dönmesi sağlandı. Geçersiz isteklere Microsoft HTTPAPI/2.0 standardında 404 sayfaları döndürüldü ve tüm istek detayları "winrm_request" olarak veritabanına loglandı.

---


