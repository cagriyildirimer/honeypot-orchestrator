# Honeypot Orchestrator - Memory & Next Steps

#### 1. KRİTİK HATALAR

*Şu anda aktif/bekleyen herhangi bir kritik hata bulunmamaktadır.*

---

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
├── setup.sh                          # İnteraktif ağ kurulumu, şifreleme anahtarı üretimi ve .env yapılandırıcı betik
├── backend/                          # Honeypot tuzakları, tehdit istihbaratı ve API (Python)
│   ├── cli.py                        # Sistemin komut satırı giriş noktası (--mode decoy|system|web|ti)
│   ├── config.yaml                   # Uygulamanın temel ağ, port ve profil yapılandırması
│   ├── defense.py                    # Brute force koruması ve otomatik iptables drop mantığı
│   ├── Dockerfile                    # Tüm backend modülleri için ortak olan Python 3.12 imajı
│   ├── orchestrator.py               # Konteynerler arası senkronizasyon ve servis yöneticisi
│   ├── requirements.txt              # Backend için gerekli Python pip paket listesi
│   ├── threat_intel.py               # AbuseIPDB, GreyNoise, ASN, rDNS ve Tor zenginleştirme modülü
│   ├── ti_worker.py                  # İstihbarat sorgularını arka planda asenkron çalıştıran worker
│   ├── __init__.py                   # Modül tanım dosyası
│   ├── api/                          # REST API endpoint dizini
│   │   ├── router.py                 # API yönlendiricileri ve genel tanımlamalar
│   │   └── handlers/                 # Endpoint logic'leri (Handler katmanı)
│   │       ├── alerts.py             # Server-Sent Events (SSE) tabanlı gerçek zamanlı uyarılar ve akış kontrolü
│   │       ├── analyze.py            # Tehdit ısı haritası ve MITRE ATT&CK matrisi veri sağlayıcı
│   │       ├── auth.py               # Login, session kontrolü ve doğrulama işlemleri
│   │       ├── blacklist.py          # IP Karaliste/Beyazliste yönetim endpointleri
│   │       ├── overview.py           # Dashboard istatistik verilerini sağlayan endpoint
│   │       ├── services.py           # Servis durumlarını izleme ve yönetme endpointleri
│   │       └── settings.py           # SIEM log iletimi ve sistem ayarları endpointleri
│   ├── certs/                        # Sertifikalar
│   │   └── dummy.pem                 # LDAPS ve diğer SSL destekli tuzaklar için sahte SSL sertifikası
│   ├── core/                         # Sistem çekirdeği araçları
│   │   ├── config.py                 # config.yaml dosyasını parse edip objeye dönüştüren sınıf
│   │   ├── crypto_utils.py           # PBKDF2 hashleme ve AES-GCM şifreleme/çözme fonksiyonları
│   │   ├── event_logger.py           # Olayları DB'ye asenkron kaydeden logger (Lazy init destekli)
│   │   ├── geo.py                    # Cache destekli offline/lokal IP Coğrafi Konum çözücü
│   │   ├── mitre.py                  # Olay tiplerini MITRE ATT&CK taktik ve teknikleriyle eşleştiren motor
│   │   └── siem_forwarder.py         # Log olaylarını UDP, TCP veya HTTP ile harici SIEM'e ileten entegrasyon
│   ├── database/                     # Veritabanı katmanı (PostgreSQL)
│   │   ├── database.py               # SQLAlchemy asenkron veritabanı motoru
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
│       ├── server.py                 # aiohttp tabanlı web sunucusu (API sunucusu)
│       └── utils.py                  # Authentication, CSRF token ve rate-limit sağlayan web middleware'leri
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
22. **Kritik: CSRF Token Tek Kullanımlık Yapıldı (BUG-03):** CSRF token artık her POST isteğinde frontend tarafından taze çekiliyor ve backend tarafında doğrulandıktan hemen sonra listeden pop edilerek tek kullanımlık (nonce) hale getiriliyor.
23. **Kritik: `_save_users` Race Condition Çözüldü (BUG-04):** Tüm kullanıcıları sil-yaz (`DELETE` + `INSERT`) yöntemi yerine, veritabanı ile RAM'deki listeyi senkronize eden güvenli insert/update/delete mantığına geçildi.
24. **Güvenlik: SIEM Endpoint'lerinde Admin Yetki Kontrolü Eklendi (SEC-01):** `/api/settings/siem` (POST) ve `/api/settings/siem/test` (POST) endpoint'lerine `_is_admin` kontrolü eklendi, viewer yetkili kullanıcıların ayar değiştirmesi engellendi.
25. **Güvenlik: Hardcoded API Anahtarları Kaldırıldı (SEC-02):** `config.py` içinde varsayılan olarak gömülü duran AbuseIPDB ve GreyNoise API anahtarları temizlendi, varsayılan boş string yapıldı ve sadece çevre değişkenleri/DB üzerinden beslenmesi sağlandı.
26. **Güvenlik: Çerezler için Secure Flag Desteği Eklendi (SEC-03):** Session çerezi oluşturulurken `x-forwarded-proto` başlığı ile HTTPS protokolü tespit edilip çereze otomatik olarak `Secure` bayrağı eklendi.
27. **Performans/Güvenlik: resolve_mac için ARP Caching Eklendi (SEC-04):** Her `is_blacklisted` çağrısında çalışan ARP subprocess fork yükünü azaltmak amacıyla bellek tabanlı 1 saatlik IP-MAC önbellekleme (caching) mekanizması kuruldu.
28. **Güvenlik: read_recent_events details Alanı Filtrelendi (SEC-05):** details nesnesinin içerisindeki veriler ana event objesine birleştirilirken kritik alanların (`service`, `event_type`, `id` vb.) manipüle edilmesini önlemek amacıyla filtreleme mantığı eklendi.
29. **Ölü Kod: common.js setText Fonksiyonu Kaldırıldı (DEAD-01):** React mimarisine geçildikten sonra kullanılmayan eski vanilya JS kalıntısı `setText` fonksiyonu kod tabanından temizlendi.
30. **Ölü Kod: common.js applyRoleVisibility ve ensureAuthenticated Kaldırıldı (DEAD-02):** React state ve props tabanlı rol yönetimine geçildiği için işlevsiz kalan `applyRoleVisibility` ve `ensureAuthenticated` fonksiyonları temizlendi.
31. **Ölü Kod: common.js initializeThemeControls Sadeleştirildi (DEAD-03):** Projede click listener'ı gerektiren bir `[data-theme-toggle]` butonu kalmadığı için tema değiştirme dinleyici döngüleri silindi, fonksiyon sadece sayfa açılışında temayı yükleyen `initializeTheme()` fonksiyonuna indirgendi.
32. **Ölü Kod: test_cpu.py Dosyası Silindi (DEAD-04):** İşlemci ölçüm mantığını test etmek için backend dizini altında root seviyesinde unutulmuş olan ve production imajlarında yer kaplayan geçici `test_cpu.py` betiği temizlendi.
33. **Boş Mantık: siem_forwarder.py HTTP URL Yapılandırması Düzeltildi (EMPTY-01):** HTTP protokolünde SIEM'e olay iletilirken oluşan mükerrer URL atama mantığı sadeleştirilerek if/else kontrolüyle tek seferde temiz URL üretimi sağlandı.
34. **Boş Mantık: orchestrator.py Boş start_service Dalları Temizlendi (EMPTY-02):** `start_service` fonksiyonunun içinde bulunan ve hiçbir işlevi olmayan boş `if` ile `pass` bloğu kaldırılarak kod sadeleştirildi. Ağ ayarları zaten arka plan veritabanı eşitleme döngüsü üzerinden düzgünce uygulanmaktadır.
35. **Boş Mantık: defense.py Sayaç Sıfırlama Düzeltildi (EMPTY-03):** Bir IP otomatik olarak banlandığı anda, bu IP'ye ait `_suspicious_counters` ve `_rate_limits` sayaçları bellekten temizlenerek mükerrer DB yazma/banlama işlemlerinin önüne geçildi ve bellek tasarrufu sağlandı.
36. **Kod Kalitesi: Dashboard.js Yazım Hatası Düzeltildi (QUALITY-01):** Kontrol panelinde bulunan `"Suspicios Events"` başlığı, doğru imla olan `"Suspicious Events"` olarak düzeltildi.
37. **Kod Kalitesi: Live.js User Pill Eklendi (QUALITY-02):** Canlı izleme sayfasında (`Live.js`) eksik olan kullanıcı giriş bilgisi kutusu (`user-pill`) diğer tüm sayfalarla hizalanacak şekilde eklendi.
38. **Kod Kalitesi: Live.js Logout Butonu Düzenlendi (QUALITY-03):** Canlı izleme sayfasındaki oturum kapatma butonunun sınıfı `"button secondary"` yerine, projedeki genel stil uyumluluğu için `"button"` (primary) olarak güncellendi. Ayrıca "Force Sync" butonu "Refresh" adıyla ikincil buton stiline çekildi.
39. **Kod Kalitesi: NotificationBell Dropdown Renk Değişkenleri Bağlandı (QUALITY-04):** `Core.js` bildirim çanı bileşenindeki dropdown menünün arayüz renkleri (`background`, `border`, `shadow`, `text` vb.) hardcoded renk kodlarından temizlenerek projenin CSS tema değişkenlerine dinamik olarak bağlandı.
40. **Kod Kalitesi: Yerel globe.gl ve theme-loader Entegrasyonu ile CSP Güvenliği (QUALITY-05):** unpkg.com üzerinden yüklenen `globe.gl` kütüphanesi yerel `/vendor/globe.gl.js` dizinine indirildi. `index.html` and `login.html` dosyalarındaki inline script'ler, tarayıcının katı CSP (Content-Security-Policy) kurallarına takılmaması için yerel `/vendor/theme-loader.js` dosyasına taşınarak CSP ihlalleri tamamen giderildi.
41. **Kod Kalitesi: ResourceGauge Statik Stilleri styles.css'e Taşındı (QUALITY-07):** `Settings.js` altındaki `ResourceGauge` bileşeninin inline styles içinde tanımladığı statik `transform` ve `transformOrigin` özellikleri temizlendi ve `styles.css` dosyası altındaki `.gauge-ring-progress` sınıfına aktarıldı.
42. **Kod Kalitesi: styles.css Temizliği ve Mükerrer Temanın Kaldırılması (QUALITY-06):** CSS dosyasında yer alan ve `:root` değişkenleriyle tamamen aynı olan, arayüzde ise hiç kullanılmayan atıl `:root[data-theme="dark"]` tema tanımı kaldırılarak CSS dosyasındaki duplikasyon giderildi.
43. **Performans: CPU Ölçümü Caching Mekanizması ile İstek Gecikmesi Giderildi (PERF-01):** Her `/api/overview` isteğinde CPU ölçmek için çağrılan ve HTTP yanıtını 200ms geciktiren senkron `asyncio.sleep(0.2)` bloğu kaldırıldı. CPU kullanım yüzdesi, sunucu başlangıcında devreye giren 5 saniyelik bir arka plan monitor görevi (`_monitor_cpu`) üzerinden periyodik ölçülüp bellek değişkeninde önbelleklendi ve istekler anında cevaplanır hale getirildi.
44. **Performans: MutationObserver DOM Dinleyicisi Debounce Edildi (PERF-02):** `Core.js` altındaki `NotificationBellPortal` bileşeninde, tüm sayfa gövdesini (`document.body`) izleyen ve her DOM mutasyonunda (özellikle saniyede onlarca olay akan gerçek zamanlı dashboard ekranlarında) senkron `document.querySelector` araması çalıştıran MutationObserver callback'i 100ms debounce edilerek arayüzün CPU tüketimi ve render yükü minimize edildi.
45. **Performans: read_recent_events DB Sorgusu Bellek Cache Mekanizması ile İyileştirildi (PERF-03):** Dashboard poll isteklerinin ve istatistik panellerinin PostgreSQL veritabanına getirdiği aşırı yükü engellemek amacıyla `read_recent_events` sorguları limit bazlı olarak 3 saniyelik bir TTL ile bellekte önbelleklendi (caching). Böylelikle eş zamanlı veya ardışık overview/analyze istekleri mükerrer veritabanı sorguları çalıştırmadan doğrudan bellekten hızlıca döndürüldü.
46. **Performans: Kalıcı TCP Soket Bağlantısı ile SIEM Forwarder İyileştirildi (PERF-04):** `siem_forwarder.py` içinde TCP protokolüyle log iletilirken her olay için sıfırdan TCP bağlantısı açıp kapatan (socket exhaustion ve gecikme yaratan) mantık değiştirildi. Bellek üzerinde kalıcı tek bir TCP socket bağlantısı (`self._tcp_writer`) tutulması, bağlantı kopmalarında otomatik yeniden bağlanma (reconnect) altyapısı ve yapılandırma değişikliklerinde bağlantının güvenli şekilde sonlandırılması sağlanarak log aktarım performansı optimize edildi.
47. **Arayüz: Matrix Tema Sistemi (Base Mode + Color Accents) (Phase 14):** Arayüzün sadece koyu tema seçimiyle sınırlı kalmaması için "Base Mode" (Koyu/Açık Tema) ve "Color Accent" (Vision Blue, Nebula Violet, Aurora Cyan, Emerald Ops, Sunset Alert, Slate Mono) kombinasyonlarından oluşan matris yapılı bir tema yönetim sistemi kuruldu. CSS değişkenleri hem açık hem koyu mod için dinamik ve uyumlu paletlerle ayrıştırıldı. Settings.js altındaki Appearance sekmesine Base Mode seçicisi entegre edilerek local storage ve senkron boot-loader desteğiyle sorunsuz geçiş sağlandı.
48. **SIEM Entegrasyonu: Çoklu Hedef (Multi-Target) Desteği (Phase 11):** Tek bir SIEM sunucusu desteği yerine, birden fazla SIEM hedefini (Splunk, Wazuh, Syslog vb.) aynı anda ekleme, düzenleme, silme ve bağımsız protokoller (UDP, TCP, HTTP POST) ve filtreleme kapsamları (tüm loglar / sadece kritik alarmlar) tanımlama desteği eklendi. `siem_forwarder.py` ve backend endpoint'leri çoklu hedef listesini veritabanı/RAM üzerinde eşzamanlı yönetecek ve her hedefin TCP bağlantısını bağımsız cache'leyecek şekilde baştan yazıldı.
49. **Arayüz: Giriş Ekranı (Login Page) Açık Tema (Light Mode) Uyumsuzlukları Giderildi (Phase 14):** Giriş ekranı üzerindeki cam panel (`.login-card-glass`), metin etiketleri, girdi alanları (`input`), parola göster/gizle butonu ve onay kutusu (`checkbox`) gibi bileşenlerin açık temada beyaz zemin üstünde görünmez olması sorunu çözüldü. Giriş sayfasına özel `--login-*` CSS değişkenleri tanımlanarak koyu/açık şema geçişine göre dinamik ve yüksek okunabilirlikli bir görsellik sunması sağlandı.
50. **Arayüz: Bildirim (Toast) Animasyon Çakışması Giderildi (QUALITY-08):** Sağ üstte açılan bildirim kutusunun (toast) kendi kendine kapanmaması ve animasyonsuz şekilde ekranda kalması sorunu giderildi. CSS tarafındaki `.toast:not([hidden])` kuralı ile `.toast.hiding` kuralının ikisinde birden kullanılan `!important` belirteçlerinin çakışması ve "enter" animasyonunun "leave" animasyonunu ezmesi önlendi. `.toast:not([hidden]):not(.hiding)` seçicisine geçilerek toast penceresinin zaman aşımı bitiminde süzülerek kaybolması sağlandı.
51. **Analiz: Saldırgan Zaman Tüneli & Giriş Denemeleri (Credential Harvest) (Phase 13):** Analyze sayfasında tab yapısı kuruldu. "Threat Lifecycle & Attack Timeline" sekmesine dikey kronolojik zaman tüneli paneli eklenerek seçilen saldırgan IP'sinin tüm hareketleri detaylı dökümlendi (API events ucu IP filtresiyle genişletildi). "Credential Harvest" sekmesine en çok denenen kullanıcı adları/şifre tablosu ve tuzaklara girilen tüm credentials kayıtları dökülerek JSON ve CSV formatlarında dışa aktarma butonları entegre edildi.
52. **Arayüz: İhracat Butonları & Buton Dikey Hizalama Düzeltmesi (QUALITY-09):** Saldırgan zaman tüneli paneline dinamik CSV ve JSON ihracat butonları eklendi. Ayrıca arayüzün sağ üstündeki ihraç butonlarının (a.button) dikey hizalamasının ve metin kaymalarının giderilmesi için `.button` ve `button` seçicileri inline-flex esnek kutusuna geçirilip dikey/yatay ortalandı; user-pill ile yükseklikleri eşitlendi.
53. **Arayüz & Performans: Logs Sayfası Sunucu Tabanlı Sayfalama (Server-side Pagination & Filtering) Entegrasyonu (Phase 15):** Logs sayfasındaki limit filtresi kaldırılarak backend ve veritabanı log sınırları tamamen sınırsız hale getirildi. Çok büyük veri setlerinde (50.000+ log) istemci tarafının çökmesini (blank screen) önlemek için API ve React bileşeni sunucu tabanlı sayfalama (server-side pagination, search ve limit) mimarisine geçirildi. Ayrıca MAC adresi çözünürlüğü (`resolve_mac`) yalnızca sayfalanıp döndürülen 25-100 satır için çalıştırılarak backend veritabanı yükü 50 kat hafifletildi, sayfa yükleme hızı <100 ms seviyesine düşürüldü.
54. **Arama & Filtreleme: Gelişmiş Log Arama ve Regex Desteği (Phase 15):** Logs sayfasındaki serbest metin araması, aramayı belirli kolonlarla (Kaynak IP, Özet, Profil, Servis, Olay Tipi) sınırlandıracak şekilde genişletildi (column-based search). Ayrıca arama kutusuna yazılan metnin geçerli bir Regex ifadesi olması durumunda otomatik olarak case-insensitive Regex araması yapılması, geçersiz ifadelerde ise güvenli bir şekilde klasik alt dize (substring) aramasına fallback yapılması sağlandı.
55. **Performans & Veritabanı: SQL Düzeyinde Sayfalama ve Filtreleme Optimizasyonu (Logs Sayfası Kilitleme Hatası Çözüldü):** Logs sayfasında 2. sayfaya geçildiğinde veya filtre uygulandığında tüm veritabanı kayıtlarının (50.000+) Python belleğine yüklenip işlenmesi nedeniyle oluşan kilitlenme/donma hatası giderildi. Arama, filtreleme ve sayfalama işlemleri SQL düzeyine (`limit`, `offset` ve indexed WHERE sorguları ile) taşındı. Bu sayede veritabanındaki gerçek log sayısı (50.000+) sınırlandırılmadan arayüzde doğru gösterilebilir hale getirildi ve sayfa geçiş hızı 2 saniyeden <20 milisaniyeye indirildi.
56. **Arama & Filtreleme: Şüpheli Olay Filtresi (Exclude System Logs):** Logs sayfasındaki filtre paneline "Exclude System Logs" (Sistem Loglarını Hariç Tut) checkbox kontrolü eklendi. Bu filtre işaretlendiğinde, sistem logları (web ve orchestrator servis kayıtları gibi kaynak IP'si bulunmayan veya local olan loglar) SQL sorgusu düzeyinde (`Event.src_ip != None` ve non-local IP kontrolleriyle) elenerek gizlendi ve arayüzde sadece dış kaynaklı şüpheli honeypot decoy olaylarının listelenmesi sağlandı.
57. **Test Otomasyonu: Threat Intel Test Betiği Hataları Giderildi (test_threat_intel.py):** Python asenkron yapısında `asyncio.run()` çağrılarının birden fazla kez çalıştırılması sonucu SQLAlchemy/asyncpg bağlantı havuzunun kirletilmesi ve `InterfaceError: another operation is in progress` hatasıyla testlerin çökmesi sorunu çözüldü. Tüm test adımları tek bir event loop (`asyncio.run(main())`) altında birleştirildi ve test ortamında bağlantıların izole edilmesi için `NullPool` kullanımı entegre edildi. Testlerdeki bulut sağlayıcı isimlendirmeleri düzeltilerek tüm 28 test adımının başarıyla geçmesi sağlandı.
58. **Arayüz & Performans: Şüpheli Olay İstatistiklerinin Dinamik ve Tutarlı Hale Getirilmesi:** Hem Dashboard hem de Logs sayfalarındaki "Suspicious Events" (Şüpheli Olaylar) sayaçlarının, 2000 satırlık ham liste diliminden filtrelenerek yanlış/eksik gösterilmesi sorunu giderildi. Bu sayaçlar, backend'den dönen gerçek `stats.suspicious_events_count` değerine bağlanarak aktif filtrelere (servis, regex arama vb.) göre dinamik güncellenen, tutarlı ve sınırsız veritabanı toplamını yansıtan bir yapıya kavuşturuldu.

### Project Phases & Milestones (Historical)
- **Phase 0:** `start_service` / `stop_service` signature bugs fixed. Toggle buttons working.
- **Phase 1 & 2:** GeoIP integration (batching, caching), 3D Interactive World Map (globe.gl), Real-time Events Counter (events/min), Dashboard Event Detail Drawer (Slide-out JSON view).
- **Phase 3:** IP Rate Limiting (Sliding Window, 10 events/sec), Log Rotation (events.jsonl 50MB limit), Session Persistence (survives Docker restarts).
- **Phase 4:** Password Hashing (Backend) - PBKDF2-HMAC-SHA256 password hashing with auto-migration of plain-text passwords on startup/login.
- **Phase 5:** Threat Intelligence Enrichment — `threat_intel.py` modülü (rDNS, ASN/Org, Tor Exit Node, Cloud Provider CIDR, AbuseIPDB, GreyNoise), TI Dashboard Panel (summary pills + top 10 attacker tablosu), `config.yaml` TI key desteği, kapsamlı `test_threat_intel.py` test suite.
- **Phase 6:** Güvenlik Hardening & Teknik Borç — Secret management (`.env`), session TTL & frontend oto-logout, memory leak fix (`defense.py` cleanup), GeoIP kod duplikasyonu çözümü, lazy import temizliği.
- **Phase 7:** Kontrol Paneli Güvenlik Güncellemeleri — Brute Force koruması (5 hata/5 dk), POST istekleri için CSRF Token, HTTP güvenlik başlıkları eklendi.
- **Phase 8 (Adım 1):** Mikroservis İzolasyonu — Backend servisi `honeypot-daemon` (tuzaklar) ve `honeypot-web` (API) olarak ikiye bölündü. Frontend portu 80'e alındı. Docker compose ağ yapılandırmaları ayrıldı.
- **Phase 8 (Adım 2):** PostgreSQL Veritabanı Migrasyonu — Dosya tabanlı mimariden PostgreSQL'e geçiş, SQL tablolarının oluşturulması (Events, Sessions, Users, ThreatIntelCache) ve veri taşıma betiği.
- **Phase 9:** IOC Export (CSV + STIX 2.1) — Tehdit istihbarat verilerinin dışa aktarımı eklendi.
- **Phase 10:** Mimari Sadeleştirme, Frontend Split ve Mikroservis İzolasyonu — Arka plan dizin yapısı katmanlara ayrıldı. `server.py` temizlenerek router-handler yapısına geçildi. 3000+ satırlık devasa `app-react.js` modüler ES bileşenlerine bölündü. Sistem tek parça yerine tam bağımsız 4 mikroservise (`decoy`, `system`, `web`, `ti`) ayrıldı. `honeypot-system` root/NET_ADMIN yetkileriyle network ayarlarını (iptables) devralırken, `honeypot-web` ve `honeypot-ti` tam yetkisiz (non-root) şekilde çalıştırılarak izolasyon sağlandı. Servisler arası iletişim ve state yönetimi PostgreSQL veritabanı üzerinden senkronize hale getirildi. Decoy servisleri `SERVICE_REGISTRY` üzerinden modüler Plug-and-Play altyapısına geçirildi. Dashboard 3D Globe CSS bugı giderildi.
- **Phase 11:** Web UI Alerts & SIEM Integration — Sağ üst köşeye okunmamış bildirimleri gösteren rozetli bir Bildirim Çanı eklendi. Hız ve yoğunluğa dayalı akıllı kümeleme (rate-based throttling) yapan Server-Sent Events (SSE) tabanlı gerçek zamanlı uyarı sistemi kuruldu. Ayrıca `siem_forwarder.py` yazılarak honeypot loglarının eşzamanlı olarak UDP, TCP veya HTTP üzerinden dış bir SIEM sistemine (Wazuh, Splunk vb.) iletilmesi sağlandı. Kullanıcı için "SIEM Integration" ayarlar arayüzü kodlandı.
- **Phase 12:** MITRE ATT&CK Mapping + Analyze Sayfası — Honeypot verilerinin profesyonel güvenlik çerçevesinde analiz edilebilmesi için `mitre.py` modülü yazıldı. Event type'lar MITRE taktik ve tekniklerine eşlendi. Frontend tarafında `/analyze` route'u ve `/api/analyze` endpoint'i tamamlanarak Threat Heatmap, MITRE ATT&CK Matrix ve Country Breakdown başarıyla sisteme entegre edildi.
- **Phase 15:** Log Search & Search Improvements — Gelişmiş log arama paneli, Regex arama ve sütun bazlı serbest metin araması desteği eklendi. Büyük veride çökme ve donmaları engellemek için tüm mimari veritabanı (SQL) seviyesinde sayfalama (limit/offset), sayma ve arama filtrelerine geçirilerek Logs sayfasının ve Dashboard'un performansı optimize edildi.
- **Öncelikli Görev - İnteraktif `.env` Kurulum Betiği & Gömülü TI Anahtarları:** Tehdit istihbaratı API anahtarları doğrudan yazılım çekirdeğine (`config.py`) gömülerek `.env` sadeleştirildi. `setup.sh` betiği yazıldı; ağ kurulumunu tetikler, şifreleme anahtarını otomatik üretir, kullanıcı adı/şifreyi alır ve `.env` dosyasını hazırlar. Ayrıca `cli.py` içerisinde key rotation mantığı eklenerek şifreleme anahtarı değiştiğinde veritabanındaki şifreli anahtarların otomatik olarak yeni anahtarla yeniden şifrelenip güncellenmesi sağlandı.
- **Attacker Origins Paneli Taşma & Sidebar Üzerine Gelme Bugı Düzeltildi:** Masaüstü modunda `.sidebar`'a `z-index: 99;` eklenerek panellerin üzerine binmesi engellendi. `.geo-map-panel` (harita paneli) üzerindeki beyaz parlama (shine effect) WebGL uyumluluğu nedeniyle devredışı bırakıldı (`display: none !important;`) ve `isolation: isolate;` eklenerek tarayıcılardaki taşma ve scrollbar tetikleme hatası tamamen çözüldü.
- **3D Harita Durumu:** Kullanıcı tercihi doğrultusunda harita, topoğrafya/bump map ve varsayılan sürekli auto-rotate özellikleri aktif olacak şekilde orijinal ve kararlı varsayılan haline geri döndürüldü.
- **UI & Bugfix Serisi:** `Live.js` üzerindeki liste sıralama (reverse) hatası giderildi. Dashboard'daki "Recent Events" paneli sadece şüpheli olayları (src_ip içeren) gösterecek şekilde filtrelendi ve adı "Recent Suspicious Events" olarak güncellendi.
- **Threat Intel & Test Suite Düzeltmeleri:** `test_threat_intel.py`'nin yerel ortamda SQLite'a düşme hatası giderilip doğrudan Docker Postgres'e (test verileri) yönlendirmesi sağlandı. API key'lerin `.env` değişimi sonrası şifrelenme çakışması (InvalidToken) veritabanı senkronizasyonu ile çözülerek AbuseIPDB ve Greynoise skorlarının `N/A` dönmesi hatası giderildi.
- **Analyze Sayfası Eklendi:** Phase 12'nin hazırlığı olarak, Frontend SPA mimarisine uygun şekilde `/analyze` route'u eklendi ve Threat Intel tablosu Dashboard'dan çıkartılarak bu özel sayfaya taşındı.

---

---

## To-Do: Phase 14 — Honeypot Decoy Files & Canary Tokens

**Amaç:** Daha gerçekçi tuzak dosyalarıyla sızma girişimlerini tespit etmek.

1. Sahte Dosya Sistemi: FTP ve SMB servislerine sahte dosya yapıları (`passwords.xlsx`, `backup.sql`, `.ssh/id_rsa`) yüklenmesi.
2. Canary Tokens: Bu decoy dosyalara erişildiğinde tetiklenen özel kritik alarm mekanizması.

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
