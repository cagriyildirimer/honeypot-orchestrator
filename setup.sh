#!/usr/bin/env bash
# Honeypot Orchestrator Interactive Setup Script
# Bu betik, Honeypot Director sisteminin ilk kurulumunu ve yapılandırmasını kolaylaştırır.
set -euo pipefail

echo "============================================="
echo "   Honeypot Director - İnteraktif Kurulum    "
echo "============================================="
echo ""

# 1. LAN Ağ Ayarlarını Yap (start-lan.sh --setup-only çalıştır)
echo "[1/4] Ağ Yapılandırması..."
if [[ ! -f "backend/scripts/start-lan.sh" ]]; then
  echo "Hata: backend/scripts/start-lan.sh bulunamadı!" >&2
  exit 1
fi

# start-lan.sh çalıştırılır. Bu betik kullanıcıya IP sorup .env dosyasına yazacaktır.
bash backend/scripts/start-lan.sh --setup-only

# 2. Şifreleme Anahtarı (Secret Key) Üretimi
echo ""
echo "[2/4] Şifreleme Anahtarı (HONEYPOT_SECRET_KEY) Üretiliyor..."

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

# Üretilen secret key'i .env dosyasına ekle
if [[ -f .env ]]; then
  grep -v "^HONEYPOT_SECRET_KEY=" .env > .env.tmp || true
  echo "HONEYPOT_SECRET_KEY=$SECRET_KEY" >> .env.tmp
  mv .env.tmp .env
else
  echo "HONEYPOT_SECRET_KEY=$SECRET_KEY" > .env
fi
echo "✓ Güvenli şifreleme anahtarı üretildi ve .env dosyasına yazıldı."

# 3. Yönetici Kullanıcı Adı ve Şifresi
echo ""
echo "[3/4] Yönetici Giriş Bilgileri Yapılandırması..."

read -p "Yönetici Kullanıcı Adı [Varsayılan: admin]: " USERNAME
USERNAME="${USERNAME:-admin}"

# Şifreyi maskeli (yazarken görünmeyen) şekilde al
read -s -p "Yönetici Şifresi [Varsayılan: admin123]: " PASSWORD
echo ""
PASSWORD="${PASSWORD:-admin123}"

# .env dosyasına kullanıcı adı ve şifreyi yaz
grep -v "^HONEYPOT_AUTH_USERNAME=" .env > .env.tmp 2>/dev/null || true
echo "HONEYPOT_AUTH_USERNAME=$USERNAME" >> .env.tmp
mv .env.tmp .env

grep -v "^HONEYPOT_AUTH_PASSWORD=" .env > .env.tmp 2>/dev/null || true
echo "HONEYPOT_AUTH_PASSWORD=$PASSWORD" >> .env.tmp
mv .env.tmp .env

echo "✓ Yönetici kullanıcı adı ve şifresi .env dosyasına yazıldı."

# 4. Kurulumu Tamamla ve Başlatma Teklifi Sun
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
  exec bash backend/scripts/start-lan.sh
else
  echo "Sistemi daha sonra başlatmak için: bash backend/scripts/start-lan.sh"
fi
