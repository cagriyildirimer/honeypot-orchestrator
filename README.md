# Honeypot Director (formerly Orchestrator)

Profil tabanlı, modüler ve lab odaklı bir honeypot yönetim sistemi. Bu sistem, modern mikroservis mimarisiyle tasarlanmış olup sahte servis listener'larını yönetir, ağ tabanlı (TCP/IP) parmak izi taklidi yapar ve siber olayları PostgreSQL üzerinde toplayarak gelişmiş bir Threat Intelligence (Tehdit İstihbaratı) analizi sunar.

Bu proje gerçek servis, exploit veya saldırı aracı değildir. Amaç kontrollü bir savunma/lab ortamında tarama, parmak izi alma ve kimlik denemesi gibi saldırgan davranışlarını gözlemlemektir.

## 🏗️ Mimari (Mikroservisler)

Proje tamamen Dockerize edilmiş ve görev odaklı mikroservislere ayrılmıştır:

- **`frontend`**: React tabanlı modern Single Page Application (SPA). Nginx üzerinden sunulur ve kullanıcıya dinamik 3D harita, istatistikler ve analiz sayfaları sunar.
- **`honeypot-web`**: FastAPI tabanlı arka plan (backend) sunucusu. Frontend'in API isteklerini karşılar, kimlik doğrulama, session yönetimi ve veritabanı okuma işlemlerini yapar. Yetkisiz (non-root) çalışır.
- **`honeypot-decoy`**: Esas tuzak servislerini (HTTP, SSH, FTP, SMB, RDP vb.) başlatan ve yöneten modüldür. `SERVICE_REGISTRY` yapısı ile eklenti (plug-and-play) mantığında çalışır.
- **`honeypot-system`**: İşletim sisteminin ağ kimliğini (sysctl TTL, TCP Window, SACK) ve dinamik güvenlik duvarı (iptables) kurallarını yönetir. Root yetkileri (`NET_ADMIN`) ile çalışır.
- **`honeypot-ti`**: Threat Intelligence (Tehdit İstihbaratı) işçisidir. Belirli aralıklarla veritabanındaki yeni IP adreslerini tarar; AbuseIPDB, GreyNoise, Tor Exit Node ve GeoIP veritabanları üzerinden saldırgan IP'lerini zenginleştirir.
- **`postgres`**: Sistem state'ini, olay (event) loglarını, kullanıcı ayarlarını ve TI önbelleğini saklayan merkezi veritabanı sunucusudur.

## 🛡️ Profiller ve Yüzeyler

- `empty`: Honeypot listener açılmaz, sadece altyapı çalışır.
- `linux_server`: HTTP, SSH, FTP ve Telnet yüzeyi sunar. TCP TTL değeri 64 olarak ayarlanır.
- `windows_server`: HTTP, DNS, NetBIOS, LDAP, LDAPS, MSSQL, RDP, SMB, LLMNR, NBTNS ve SSH yüzeyi sunar. TCP TTL değeri 128 yapılır, TCP pencereleri Windows Server mimarisine benzetilir.

Profil değişimi panelden tek tuşla atomik olarak yapılır. Bir servis başlatılamazsa orkestratör önceki profil durumuna güvenli şekilde geri döner (rollback).

## 🕸️ Ağ Ayarları ve Kimlik Taklidi (Network Tuning)

Orkestratör, uygulanan profile göre konteynerin ağ ad alanında (network namespace) çekirdek parametrelerini değiştirerek TCP/IP parmak izi (fingerprint) taklidi gerçekleştirir:
- **Windows Emülasyonu**: Varsayılan TTL değeri `128` yapılır, TCP zaman damgaları kapatılır, SACK ve Windows tarzı TCP tampon boyutları ayarlanarak Nmap gibi gelişmiş tarayıcıların "OS Detection" yetenekleri yanıltılır.
- **Dinamik Güvenlik Duvarı (iptables)**: Sadece açık olması gereken honeypot portlarına izin verilir. Diğer tüm bağlantılar ve ICMP/Ping provaları sessizce DROP edilerek açık olmayan portlar hakkında saldırgana bilgi verilmez.
- **Deep OS Fake (NFQUEUE)**: TCP Seçenek sıralaması (TCP Options) ve IP ID üretimi, arka plandaki `packet_mangler` servisi ile paket bazında modifiye edilerek Linux çekirdeğinin statik yapısı tamamen maskelenir.

## 🚨 Güvenlik & Otomatik Engelleme (Defense)

- **Otomatik IP Engelleme**: Güvenli listede olmayan dış IP'ler belirli bir limitten fazla bağlantı denemesi (brute-force/scan) yaptığında otomatik kara listeye (blacklist) alınır.
- **Pre-Connection Filtresi**: TCP tuzakları, gelen bağlantıları socket seviyesinde filtreler; kara listedeki IP'ler direkt düşürülür.
- **Web Paneli Koruması**: Dashboard girişi PBKDF2 ile şifrelenmiştir ve brute-force korumalıdır (5 hata / 5 dakika limit). Oturumlar JWT/Cookie bazlı olarak yönetilir.

## 📊 Dashboard ve Arayüz

Sistemi başlattıktan sonra panele erişim sağlayabilirsiniz. (Docker port map ayarlarına göre port değişebilir, varsayılan `80` veya `8080`).

Varsayılan giriş bilgileri (`.env` üzerinden değiştirilebilir):
```text
Username: admin
Password: admin123
```

Kullanıcı yetkileri (RBAC):
- **`admin`**: Profili değiştirebilir, sistem ayarlarını yönetebilir, kara/beyaz listeyi düzenleyebilir.
- **`viewer`**: Sadece olay akışını, 3D haritayı, analiz (TI) sayfasını ve logları izleyebilir.

## 🚀 Başlangıç

Sistem tamamen Docker tabanlıdır. Lokalinizde Python ortamı kurmanıza gerek yoktur.
Başlatmak için:
```bash
docker-compose up -d --build
```
Durdurmak için:
```bash
docker-compose down
```

Tüm sistem verisi Docker volume (`pgdata`) aracılığıyla korunur.

## 🌐 Ubuntu LAN Modu (Gerçek Ağda Yayınlama)

Sistemi ev veya ofis ağınızda gerçek bir cihazmış gibi yayınlamak isterseniz `macvlan` ağı kullanan LAN modunu kullanabilirsiniz:
```bash
scripts/start-lan.sh --ip 192.168.1.240
```
Bu bash betiği, Linux ana makinenizin alt ağını ve varsayılan geçidini otomatik tespit ederek honeypot'u doğrudan fiziksel modeminize bağlar. (Host makineniz üzerinden macvlan IP'sine erişemezsiniz, ağdaki başka bir bilgisayardan test etmeniz gerekir).

## 🔧 Konfigürasyon ve `.env`

Uygulamanın varsayılan parametreleri `config.yaml` dosyasında bulunur, ancak ortam değişkenleri önceliklidir.
Ana proje dizininde bir `.env` dosyası oluşturarak şu ayarları yapabilirsiniz:
```dotenv
HONEYPOT_AUTH_USERNAME=admin
HONEYPOT_AUTH_PASSWORD=GuvenliSifre123
HONEYPOT_SECRET_KEY=super_gizli_sifreleme_anahtari
HONEYPOT_TI_ABUSEIPDB_KEY=abuse_ipdb_api_key_buraya
HONEYPOT_TI_GREYNOISE_KEY=greynoise_api_key_buraya
```

## ⚠️ Güvenlik Sınırı

Bu proje **yalnızca savunma ve analiz amaçlı lab kullanımı** içindir. Sistemin tasarımı gerçek ağlarda bir sızma denemesi (exploit execution) barındırmaz. Kurulumu yaparken zayıf veya varsayılan şifreleri internete açık ortamlarda kullanmaktan kaçının.
