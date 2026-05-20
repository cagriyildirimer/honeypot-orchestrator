# Honeypot Orchestrator

Profil tabanlı, lab odaklı bir honeypot orkestratörü. Uygulama tek Python prosesi içinde sahte servis listener'larını yönetir, olayları JSONL olarak toplar ve dahili web panelinden aktif profili değiştirmenizi sağlar.

Bu proje gerçek servis, exploit veya saldırı aracı değildir. Amaç kontrollü bir savunma/lab ortamında tarama, parmak izi alma ve kimlik denemesi gibi davranışları gözlemlemektir.

## Mimari

Proje küçük ve bağımlılıksız tutulmuştur:

- `honeypot_orchestrator/config.py`: `config.yaml` dosyasını ve `HONEYPOT_*` environment override'larını yükler.
- `honeypot_orchestrator/profiles.py`: Hazır host profillerini tanımlar.
- `honeypot_orchestrator/services/`: Decoy servis implementasyonları ve `SERVICE_REGISTRY`.
- `honeypot_orchestrator/orchestrator.py`: Profil uygulama, servis başlatma/durdurma ve rollback mantığını yönetir.
- `honeypot_orchestrator/web/server.py`: Minimal asyncio HTTP sunucusu, dashboard, auth ve JSON API katmanı.
- `honeypot_orchestrator/web/static/app-react.js`: Harici build adımı gerektirmeyen React tabanlı tek sayfa panel.

Başlangıçta `empty` profil uygulanır; bu profil honeypot listener açmaz. Listener'lar dashboard üzerinden `linux_server` veya `windows_server` profili seçildiğinde başlar.

## Profiller

- `empty`: Sadece web paneli çalışır, honeypot listener açılmaz.
- `linux_server`: HTTP, SSH, FTP ve Telnet yüzeyi sunar.
- `windows_server`: HTTP, DNS, NetBIOS, LDAP, LDAPS, MSSQL, RDP ve SMB yüzeyi sunar.

Profil değişimi atomik yapılmaya çalışılır. Bir servis başlatılamazsa orchestrator önceki profil durumuna geri dönmeye çalışır.

## Dashboard

Varsayılan adres:

```text
http://127.0.0.1:8000
```

Varsayılan giriş bilgileri:

```text
Username: admin
Password: admin123
```

Panelden aktif profil, servis durumları, olay akışı, log özeti, tema, log dışa aktarma/temizleme ve kullanıcı yönetimi görülebilir. Admin olmayan kullanıcılar olayları izleyebilir; profil, log temizleme ve kullanıcı yönetimi admin yetkisi ister.

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
- HTTP: `8080`
- SSH: `2222`
- FTP: `2121`
- Telnet: `2323`
- DNS over TCP: `1053`
- NetBIOS: `139`
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

LAN modu macvlan kullanır. Container kendi LAN IP adresini alır ve servisleri standart portlarda gösterebilir.

Hazırlama ve başlatma:

```bash
scripts/start-lan.sh --ip 192.168.1.240 --detached
```

Manuel compose:

```bash
docker compose -f docker-compose.lan.yml up -d --build
```

Notlar:

- `HONEYPOT_LAN_IP` LAN içinde boş ve tercihen DHCP'de rezerve edilmiş bir adres olmalı.
- macvlan modunda Ubuntu host çoğu zaman container IP'ye doğrudan erişemez; aynı LAN'daki başka bir cihazdan test etmek daha doğrudur.
- LAN modunda HTTP `80`, SSH `22`, FTP `21`, Telnet `23`, DNS `53`, SMB `445` gibi standart portlara alınır.

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
