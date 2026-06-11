# Honeypot Orchestrator

Profil tabanlı, lab odaklı bir honeypot orkestratörü. Uygulama tek Python prosesi içinde sahte servis listener'larını yönetir, olayları JSONL olarak toplar ve dahili web panelinden aktif profili değiştirmenizi sağlar.

Bu proje gerçek servis, exploit veya saldırı aracı değildir. Amaç kontrollü bir savunma/lab ortamında tarama, parmak izi alma ve kimlik denemesi gibi davranışları gözlemlemektir.

## Mimari

Proje küçük ve bağımlılıksız tutulmuştur:

- `honeypot_orchestrator/config.py`: `config.yaml` dosyasını ve `HONEYPOT_*` environment override'larını yükler.
- `honeypot_orchestrator/profiles.py`: Hazır host profillerini tanımlar.
- `honeypot_orchestrator/services/`: Decoy servis implementasyonları ve `SERVICE_REGISTRY`.
- `honeypot_orchestrator/orchestrator.py`: Profil uygulama, servis başlatma/durdurma ve rollback mantığını yönetir.
- `honeypot_orchestrator/web/server.py`: Minimal asyncio HTTP sunucusu, dashboard, auth, yetkilendirme ve JSON API katmanı.
- `honeypot_orchestrator/web/static/app-react.js`: Harici build adımı gerektirmeyen React tabanlı tek sayfa panel.
- `honeypot_orchestrator/net_tuner.py`: İşletim sistemi ağ kimliğini taklit etmek için sysctl TTL ve TCP zaman damgası parametrelerini düzenler.
- `honeypot_orchestrator/defense.py`: Kara liste/beyaz liste yönetimini, MAC adresi çözümlemeyi ve otomatik IP engellemeyi kontrol eder.

Başlangıçta `empty` profil uygulanır; bu profil honeypot listener açmaz. Listener'lar dashboard üzerinden `linux_server` veya `windows_server` profili seçildiğinde başlar.

## Profiller

- `empty`: Sadece web paneli çalışır, honeypot listener açılmaz.
- `linux_server`: HTTP, SSH, FTP ve Telnet yüzeyi sunar.
- `windows_server`: HTTP, DNS, NetBIOS, LDAP, LDAPS, MSSQL, RDP, SMB, LLMNR, NBTNS ve SSH yüzeyi sunar.

Profil değişimi atomik yapılmaya çalışılır. Bir servis başlatılamazsa orchestrator önceki profil durumuna geri dönmeye çalışır.

## Ağ Ayarları ve Kimlik Taklidi (Network Tuning)

Orkestratör, uygulanan profile göre konteynerin ağ ad alanında (network namespace) sysctl parametrelerini değiştirerek TCP/IP parmak izi (fingerprint) taklidi gerçekleştirir:
- **`windows_server` profili**: Varsayılan TTL değeri `128` yapılır ve TCP zaman damgaları kapatılır (`tcp_timestamps=0`).
- **`linux_server` veya `empty` profili**: Varsayılan TTL değeri `64` yapılır ve TCP zaman damgaları açılır (`tcp_timestamps=1`).

Bu sayede saldırganların `ping` veya `nmap` taramalarında işletim sistemini doğru tahmin etmeleri (OS fingerprinting) simüle edilir. Konteynerin bu ayarları uygulayabilmesi için `cap_add: [NET_ADMIN]` yetkisine sahip olması gerekir. Yetki yoksa orkestratör hata vermez, bir uyarı logu oluşturarak çalışmaya devam eder.

## Güvenlik & Otomatik Engelleme (Defense)

Sistem, orkestratör seviyesinde dinamik bir savunma mekanizması sunar:
- **Beyaz/Kara Liste (`logs/whitelist.json`, `logs/blacklist.json`)**: Engellenen ve izin verilen IP adresleri JSON dosyalarında tutulur.
- **MAC Adresi Çözümleme**: Saldırganın IP adresinden yerel ağdaki MAC adresi dynamic olarak çözümlenir (`arp -a` veya `arp -n` komutları yardımıyla). Blacklist kontrolünde MAC eşleşmesi de dikkate alınır.
- **Otomatik IP Engelleme**: Güvenli listede (whitelist) yer almayan bir istemci IP adresi honeypot servislerine 100 veya daha fazla bağlantı denemesi (şüpheli etkinlik) yaptığında otomatik olarak kara listeye eklenir.
- **Pre-Connection Filtresi**: TCP decoys, gelen bağlantıları henüz protokol işlemeden önce filtreler; kara listedeki bir IP veya MAC adresinden gelen bağlantılar derhal sonlandırılır.

## Dashboard ve Yetki Yönetimi (RBAC)

Varsayılan adres:

```text
http://127.0.0.1:8000
```

Varsayılan giriş bilgileri:

```text
Username: admin
Password: admin123
```

Kullanıcı yetkilendirmesi iki farklı role ayrılmıştır:
- **`admin` rolü**: Aktif profili değiştirebilir, kullanıcıları yönetebilir (kullanıcı ekleme, silme, rol/şifre değiştirme), kara liste/beyaz liste düzenleyebilir, logları temizleyebilir ve dışa aktarabilir.
- **`viewer` rolü**: Panelde sadece canlı olay akışını (`/live`), sistem genel durumunu ve log özetlerini izleyebilir. Herhangi bir yapılandırma değişikliği yapamaz.

Oturumlar sunucu tarafında bellek üzerinde saklanan session cookie'leri ile doğrulanır. Kullanıcı veri tabanı `logs/web_users.json` yolunda şifreli/düz metin olarak saklanır.

## Lokal Çalıştırma

```bash
py -m honeypot_orchestrator.cli --config config.yaml
```

Linux/macOS veya PATH içinde `python` doğru kuruluysa:

```bash
python -m honeypot_orchestrator.cli --config config.yaml
```

Varsayılan lab portları:

- web paneli: `8000`
- HTTP Linux: `8080`
- HTTP Windows: `80`
- SSH Linux: `2222`
- SSH Windows: `2223`
- FTP: `2121`
- Telnet: `2323`
- DNS (TCP): `1053`
- NetBIOS: `139`
- NBTNS (NetBIOS Name Service - UDP): `137`
- LLMNR (UDP): `5355`
- LDAP: `389`
- LDAPS: `636`
- MSSQL: `1433`
- RDP: `3389`
- SMB: `1445`

## Docker

Host port publish modunda çalıştırma:

```bash
docker compose up -d --build
```

Durdurma:

```bash
docker compose down
```

Container içinde log yolu varsayılan olarak `/app/logs/events.jsonl` olur ve `honeypot_logs` volume'una yazılır.

## Ubuntu LAN Modu

LAN modu `macvlan` ağ sürücüsünü kullanır. Container, ev veya ofis ağınızdaki herhangi bir fiziksel bilgisayar gibi doğrudan modeme/anahtara bağlanarak kendi bağımsız LAN IP adresini alır. Böylece tüm honeypot servisleri kendi gerçek standart portlarında (HTTP 80, SSH 22, SMB 445 vb.) çalıştırılabilir.

### Otomatik Başlatma Betiği (`scripts/start-lan.sh`)

Sistemde LAN kurulumunu otomatikleştiren bir Bash betiği yer alır. Bu betik ağ kartını, alt ağı ve varsayılan geçidi otomatik tespit ederek macvlan ağını kurar.

Kullanım parametreleri:

- `--ip LAN_IP`: Konteynere atanacak boş ve statik LAN IP adresi (örn. `192.168.1.240`). Belirtilmezse, alt ağda ping yanıtı vermeyen boş bir yüksek IP adresi önerilir.
- `--parent IFACE`: macvlan ağının bağlanacağı fiziksel ağ arayüzü (örn. `eth0` veya `enp3s0`). Belirtilmezse varsayılan ağ geçidine sahip olan arayüz otomatik seçilir.
- `--subnet CIDR`: Yerel ağın CIDR biçimindeki tanımı (örn. `192.168.1.0/24`).
- `--gateway IP`: Ağ geçidi IP adresi (örn. `192.168.1.1`).
- `--network NAME`: Oluşturulacak docker macvlan ağının adı. Varsayılan: `honeypot_lan_net`.
- `--detached` veya `-d`: Konteyneri arka planda (detached) başlatır.
- `--recreate-network`: Mevcut macvlan ağını silip sıfırdan yeniden oluşturur.

Örnek çalıştırma:

```bash
# IP adresini otomatik seçtirerek etkileşimli başlatma
scripts/start-lan.sh

# Belirli bir statik IP ile arka planda başlatma
scripts/start-lan.sh --ip 192.168.1.240 -d

# Arayüz ve ağ detaylarını elle belirterek ağ ağını yeniden oluşturma
scripts/start-lan.sh --ip 192.168.1.240 --parent eth0 --subnet 192.168.1.0/24 --gateway 192.168.1.1 --recreate-network -d
```

### Manuel LAN Yayını

Otomatik betik yerine adımları manuel işletmek isterseniz:

```bash
docker compose -f docker-compose.lan.yml up -d --build
```

**Notlar:**
- `HONEYPOT_LAN_IP` yerel ağda IP çakışması yaratmayacak, DHCP havuzunun dışında rezerve edilmiş bir IP olmalıdır.
- macvlan güvenlik sınırları gereği, ana makinenin (host) kendisi doğrudan konteynerin macvlan IP'sine erişemez. Testleri ağdaki başka bir bilgisayardan veya cihazdan yapmanız gerekir.
- LAN modunda servis portları `.env` dosyasına yazılan değerler doğrultusunda standart portlara (HTTP `80`, SSH `22`, FTP `21`, Telnet `23`, DNS `53`, SMB `445` vb.) çekilir.

## Konfigürasyon

Ana dosya `config.yaml`.

Önemli alanlar:

- `profile`
- `web.host`
- `web.port`
- `auth.username`
- `auth.password`
- `logging.path`
- `services.<name>.enabled`
- `services.<name>.host`
- `services.<name>.port`

Sık kullanılan environment override'ları:

- `HONEYPOT_PROFILE`
- `HONEYPOT_HOST`
- `HONEYPOT_WEB_HOST`
- `HONEYPOT_WEB_PORT`
- `HONEYPOT_AUTH_USERNAME`
- `HONEYPOT_AUTH_PASSWORD`
- `HONEYPOT_LOG_PATH`
- `HONEYPOT_SERVICE_HTTP_PORT`
- `HONEYPOT_SERVICE_SMB_PORT`
- `HONEYPOT_SERVICE_MSSQL_PORT`

## Loglama

Olaylar JSONL formatında yazılır.

Varsayılan yollar:

- Lokal: `logs/events.jsonl`
- Container: `/app/logs/events.jsonl`

Tipik alanlar:

- `timestamp`
- `service`
- `event_type`
- `src_ip`
- `src_port`
- `summary`

Protokole göre ek alanlar:

- `username`
- `password`
- `domain`
- `workstation`
- `user_agent`
- `query_name`
- `query_type`

## Doğrulama

Python bytecode derleme:

```bash
py -m compileall honeypot_orchestrator
```

Unit testler:

```bash
py -m unittest discover
```

Docker build:

```bash
docker compose build
```

## Güvenlik Sınırı

Bu proje yalnızca savunma amaçlı lab kullanımı içindir.

Amaçlamadığı şeyler:

- gerçek exploit çalıştırma
- malware davranışı
- kalıcı erişim
- otomatik saldırı zinciri
- yetki yükseltme
- yatay hareket

Varsayılan parolaları gerçek ağda kullanmayın. LAN modunda servisleri görünür hale getirmeden önce hedef ağın size ait ve kontrollü olduğundan emin olun.
