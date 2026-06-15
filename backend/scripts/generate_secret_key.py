#!/usr/bin/env python3
import sys

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Hata: 'cryptography' kütüphanesi bulunamadı.")
    print("Önce yüklemek için: pip install cryptography")
    sys.exit(1)

def main():
    print("--- Honeypot Orchestrator Secret Key Generator ---")
    key = Fernet.generate_key().decode()
    print("\nYeni üretilen güvenli anahtarınız:\n")
    print(f"HONEYPOT_SECRET_KEY={key}\n")
    print("Lütfen bu satırı .env dosyanızın içerisine yapıştırın.")
    print("Dikkat: Bu anahtarı kaybetmeyin, şifrelenmiş API verileriniz bu anahtara bağlıdır!")

if __name__ == "__main__":
    main()
