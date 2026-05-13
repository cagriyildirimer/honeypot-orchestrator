# Honeypot Orchestrator

Lab ortamları için tasarlanmış, profil tabanlı bir honeypot orkestratörü. Uygulama tek bir proses içinde birden fazla sahte servisi yönetir, olayları JSONL olarak toplar ve hafif bir web paneli üzerinden aktif profili değiştirmenize izin verir.

## Mimari

Proje üç ana katmandan oluşur:

- `honeypot_orchestrator/orchestrator.py`
  Tüm servislerin yaşam döngüsünü yönetir. Uygulama açılışında `empty` profilini uygular, seçilen profile göre listener'ları başlatır veya durdurur.
- `honeypot_orchestrator/services/`
  HTTP, SSH, FTP, Telnet, DNS, NetBIOS, LDAP, LDAPS, MSSQL, RDP ve SMB gibi decoy servisler burada yer alır.
- `honeypot_orchestrator/web/server.py`
  Dahili dashboard, login, logs ve JSON API katmanını sağlar.

Temel davranış:

- Konfig dosyası `config.yaml` ile yüklenir.
- Ortak log dosyası `logs/events.jsonl` veya container içinde `/app/logs/events.jsonl` olarak kullanılır.
- Uygulama başlangıçta yalnızca web panelini açabilir.
- Gerçek honeypot listener'ları, seçilen profil uygulandığında devreye girer.

## Profiller

Hazır profiller:

- `empty`
  Başlangıç profili. Listener açmaz.
- `linux_server`
  HTTP, SSH, FTP ve Telnet benzeri Linux yüzeyi sunar.
- `windows_server`
  HTTP, DNS, NetBIOS, LDAP, LDAPS, MSSQL, RDP ve SMB benzeri Windows Server yüzeyi sunar.

Profil değişimi UI üzerinden yapılır; servisler tek tek panelden manuel açılıp kapanmaz.

## Dashboard

Varsayılan dashboard adresi:

```text
http://127.0.0.1:8000
```

Varsayılan giriş bilgileri:

- Username: `admin`
- Password: `admin123`

Dashboard tarafında:

- aktif profil görülür
- profil değişikliği uygulanır
- servislerin dinleyip dinlemediği izlenir
- son olaylar ve log özeti görülür

## Lokal Çalıştırma

Python ile doğrudan çalıştırmak için:

```bash
python -m honeypot_orchestrator.cli --config config.yaml
```

Bu akışta:

- web paneli `8000`
- lab portları varsayılan olarak `8080`, `2222`, `2121`, `2323`, `1053`, `139`, `389`, `636`, `1433`, `3389`, `1445`

üzerinden kullanılır.

## Docker

Normal Docker Compose çalıştırma:

```bash
docker compose up -d --build
```

Eski `docker-compose` binary kullanıyorsanız eşdeğer komut:

```bash
docker-compose up -d --build
```

Bu mod host port publish mantığıyla çalışır ve geliştirme veya temel lab kullanımına uygundur.

## Ubuntu LAN Modu

Daha gerçekçi kullanım akışı Ubuntu üzerinde macvlan tabanlı LAN modu ile çalışmaktır. Bu modda container kendi LAN IP adresine sahip olur ve servisler standart portlarda görünebilir.

### 1. Yardımcı script ile LAN ortamını hazırla

İlk adım:

```bash
scripts/start-lan.sh
```

IP'yi açıkça vermek isterseniz:

```bash
scripts/start-lan.sh --ip 192.168.12.240
```

Bu script:

- varsayılan ağ arayüzünü bulur
- subnet ve gateway bilgisini çıkarır
- macvlan Docker network'ünü oluşturur veya yeniden kullanır
- host-published stack açıksa onu indirir
- LAN için gerekli environment değişkenlerini hazırlar

### 2. LAN stack'i ayağa kaldır

İkinci adım:

```bash
docker-compose -f docker-compose.lan.yml up -d --build
```

`docker compose` kullanıyorsan eşdeğeri:

```bash
docker compose -f docker-compose.lan.yml up -d --build
```

Bu dosya:

- servisleri standart portlara bind edecek environment override'larını verir
- container'ı harici macvlan network'e bağlar
- dashboard'ı `8000`
- SMB'yi `445`
- MSSQL'i `1433`
- RDP'yi `3389`

gibi gerçek portlarda sunar.

### 3. Dashboard'a container IP üzerinden bağlan

LAN modunda dashboard host IP değil, container IP üzerinden açılır:

```text
http://192.168.12.240:8000
```

Notlar:

- `HONEYPOT_LAN_IP` ağ içinde boş ve rezerve bir adres olmalı.
- macvlan kullanımında Ubuntu host çoğu zaman container IP'ye doğrudan erişemez.
- Dashboard'ı aynı LAN üzerindeki farklı bir makineden test etmek daha doğrudur.

## Konfig

Temel ayarlar `config.yaml` içindedir.

Önemli alanlar:

- `profile`
- `web.host`
- `web.port`
- `services.<name>.enabled`
- `services.<name>.host`
- `services.<name>.port`
- `logging.path`

Birçok değer environment variable ile override edilebilir. Örnekler:

- `HONEYPOT_PROFILE`
- `HONEYPOT_WEB_HOST`
- `HONEYPOT_WEB_PORT`
- `HONEYPOT_AUTH_USERNAME`
- `HONEYPOT_AUTH_PASSWORD`
- `HONEYPOT_LOG_PATH`
- `HONEYPOT_SERVICE_HTTP_PORT`
- `HONEYPOT_SERVICE_SMB_PORT`
- `HONEYPOT_SERVICE_MSSQL_PORT`

## Loglama

Tüm olaylar JSONL formatında yazılır.

Varsayılan yollar:

- lokal çalışmada `logs/events.jsonl`
- container içinde `/app/logs/events.jsonl`

Kayıtlarda sık görülen alanlar:

- `timestamp`
- `service`
- `event_type`
- `src_ip`
- `src_port`
- `summary`

Bazı protokoller ek alanlar da yazar:

- `username`
- `password`
- `domain`
- `workstation`
- `user_agent`
- `query_name`

## Servisler

Mevcut servisler:

- HTTP
- SSH
- FTP
- Telnet
- DNS over TCP
- NetBIOS Session Service
- LDAP
- LDAPS
- MSSQL
- RDP
- SMB

Bu servisler gerçek servis implementasyonu sunmaz; amaçları tarama, parmak izi ve kimlik denemesi gibi davranışları gözlemlemektir.

## Sık Kullanılan Komutlar

Lokal compose:

```bash
docker compose up -d --build
```

Lokal compose durdurma:

```bash
docker compose down
```

Ubuntu LAN modu hazırlama:

```bash
scripts/start-lan.sh --ip 192.168.1.240
```

Ubuntu LAN stack başlatma:

```bash
docker-compose -f docker-compose.lan.yml up -d --build
```

LAN stack durdurma:

```bash
docker-compose -f docker-compose.lan.yml down
```

## Güvenlik Sınırı

Bu proje savunma amaçlı lab ortamları içindir.

Şunları amaçlamaz:

- gerçek exploit çalıştırma
- malware davranışı
- kalıcı erişim
- otomatik saldırı zinciri
- yetki yükselme veya yatay hareket

Amaç, saldırgan benzeri trafik ve kimlik denemelerini kontrollü şekilde gözlemlemektir.
