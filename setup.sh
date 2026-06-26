#!/usr/bin/env bash
# Honeypot Orchestrator Interactive Setup Script
# Bu betik, Honeypot Director sisteminin ilk kurulumunu ve yapılandırmasını kolaylaştırır.
set -euo pipefail

echo "============================================="
echo "   Honeypot Director - İnteraktif Kurulum    "
echo "============================================="
echo ""

# 1. Kurulum Türü Seçimi
echo "Lütfen kurulum türünü seçiniz:"
echo "1) Standart Kurulum (Varsayılan Docker port köprüleme, ağ yapılandırması gerektirmez)"
echo "2) Macvlan / LAN Kurulumu (Yerel ağdan doğrudan IP tahsis etme, macvlan gerektirir)"
read -p "Seçiminiz [1 veya 2, Önerilen: 2]: " INSTALL_TYPE
INSTALL_TYPE="${INSTALL_TYPE:-2}"

# .env dosyasını sıfırdan oluşturmak için hazırla
if [[ -f .env ]]; then
  # Mevcut .env varsa yedekle
  cp .env .env.bak
  echo "✓ Mevcut .env dosyası .env.bak olarak yedeklendi."
fi

# Temiz bir .env dosyası başlatalım
echo "# Honeypot Director Environment Settings" > .env

# Ağ Yapılandırma Adımı
if [[ "$INSTALL_TYPE" == "2" ]]; then
  echo ""
  echo "[1/3] Macvlan Ağ Yapılandırması Başlatılıyor..."
  if [[ ! -f "backend/scripts/start-lan.sh" ]]; then
    echo "Hata: backend/scripts/start-lan.sh bulunamadı!" >&2
    exit 1
  fi
  
  # start-lan.sh çalıştırılır. Bu betik ağ ayarlarını yapıp HONEYPOT_LAN_IP'yi .env'ye yazacaktır.
  bash backend/scripts/start-lan.sh --setup-only
  echo "✓ Macvlan ağ ayarları ve IP başarıyla yapılandırıldı."
else
  echo ""
  echo "[1/3] Standart Kurulum Yapılandırması..."
  echo "HONEYPOT_LAN_IP=" >> .env
  echo "✓ Standart mod seçildi (Yerel IP adresi atanmadı)."
fi

# 2. Şifreleme Anahtarı (Secret Key) Üretimi
echo ""
echo "[2/3] Şifreleme Anahtarı (HONEYPOT_SECRET_KEY) Üretiliyor..."

SECRET_KEY=""
# Python ile Fernet uyumlu anahtar üretmeyi dene
if command -v python3 >/dev/null 2>&1; then
  SECRET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || true)
elif command -v python >/dev/null 2>&1; then
  SECRET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || true)
fi

# Python/cryptography başarısız olursa openssl kullan
if [[ -z "$SECRET_KEY" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    SECRET_KEY=$(openssl rand -base64 32 2>/dev/null | tr -d '\n\r' || true)
  fi
fi

if [[ -z "$SECRET_KEY" ]]; then
  echo "Hata: Şifreleme anahtarı üretilemedi (python/cryptography veya openssl eksik)!" >&2
  exit 1
fi

echo "HONEYPOT_SECRET_KEY=$SECRET_KEY" >> .env
echo "✓ Güvenli şifreleme anahtarı otomatik üretildi ve yazıldı."

# 3. Yönetici Kullanıcı Adı ve Şifresi
echo ""
echo "[3/3] Yönetici Giriş Bilgileri Yapılandırması..."

read -p "Yönetici Kullanıcı Adı [Varsayılan: admin]: " USERNAME
USERNAME="${USERNAME:-admin}"

# Şifreyi maskeli (yazarken görünmeyen) şekilde al
read -s -p "Yönetici Şifresi [Varsayılan: admin123]: " PASSWORD
echo ""
PASSWORD="${PASSWORD:-admin123}"

echo "HONEYPOT_AUTH_USERNAME=$USERNAME" >> .env
echo "HONEYPOT_AUTH_PASSWORD=$PASSWORD" >> .env
echo "✓ Yönetici bilgileri .env dosyasına yazıldı."

# 4. Kurulumu Tamamla ve Başlatma
echo ""
echo "============================================="
echo "   Kurulum Başarıyla Tamamlandı! 🎉          "
echo "============================================="
echo ""
echo "Oluşturulan .env dosyası içeriği:"
cat .env
echo ""

read -p "Honeypot sistemini şimdi başlatmak ister misiniz? [y/N]: " START_NOW
if [[ "$START_NOW" =~ ^[yY](es|ES)?$ ]]; then
  echo "Sistem başlatılıyor..."
  if [[ "$INSTALL_TYPE" == "2" ]]; then
    exec bash backend/scripts/start-lan.sh
  else
    exec docker compose up --build
  fi
else
  if [[ "$INSTALL_TYPE" == "2" ]]; then
    echo "Sistemi daha sonra başlatmak için: bash backend/scripts/start-lan.sh"
  else
    echo "Sistemi daha sonra başlatmak için: docker compose up --build"
  fi
fi
