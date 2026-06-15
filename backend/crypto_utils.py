import os
from cryptography.fernet import Fernet
import base64

def get_secret_key() -> bytes:
    """
    Returns the master secret key for symmetric encryption.
    If HONEYPOT_SECRET_KEY is not in env, it raises an error (or generates one if we want).
    For now, we expect it to be a valid base64 32-byte key.
    """
    key_str = os.environ.get("HONEYPOT_SECRET_KEY", "")
    if not key_str:
        # Generate a fallback key based on some unique system property or just a default 
        # (NOT recommended for production, but prevents crashes if missing)
        # It's better to log a warning.
        print("WARNING: HONEYPOT_SECRET_KEY is not set in environment! Using a temporary key.")
        return Fernet.generate_key()
    
    try:
        # Ensure it's valid base64
        # Fernet keys must be 32 url-safe base64-encoded bytes
        if len(key_str) == 44:
            return key_str.encode("utf-8")
        else:
            # Maybe the user entered a random string. Hash it to 32 bytes and base64 encode it
            import hashlib
            m = hashlib.sha256()
            m.update(key_str.encode("utf-8"))
            return base64.urlsafe_b64encode(m.digest())
    except Exception:
        return Fernet.generate_key()

_fernet_instance = None

def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        _fernet_instance = Fernet(get_secret_key())
    return _fernet_instance

def encrypt_value(plaintext: str) -> str:
    if not plaintext:
        return ""
    f = _get_fernet()
    token = f.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")

def decrypt_value(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        f = _get_fernet()
        plaintext = f.decrypt(ciphertext.encode("utf-8"))
        return plaintext.decode("utf-8")
    except Exception as e:
        print(f"Error decrypting value: {e}")
        return ""
