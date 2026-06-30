"""
PhantomVault — Cryptography Core
═══════════════════════════════════════════════════════════════
Master password → Scrypt KDF → 256-bit key → AES-256-GCM encrypt/decrypt.

Design choices (documented so you understand exactly what's protecting
your data — never trust a crypto tool you can't explain):

  • KDF: Scrypt (memory-hard — far more GPU/ASIC-resistant than PBKDF2)
    Parameters: N=2^14, r=8, p=1  (≈ standard "interactive" Scrypt cost,
    libsodium's crypto_pwhash uses similar interactive-tier parameters)
  • Cipher: AES-256-GCM (authenticated encryption — tampering with the
    ciphertext causes decryption to FAIL LOUDLY rather than silently
    returning garbage)
  • Salt: 16 random bytes, generated once when the vault is created,
    stored in plaintext alongside the ciphertext (this is correct and
    standard — salts are not secret, they just prevent rainbow tables)
  • Nonce: 12 random bytes, generated FRESH on every single save
    (critical: reusing a nonce with the same key breaks GCM's security
    guarantees completely)

The master password itself is NEVER stored anywhere, in any form.
If you forget it, the vault is cryptographically unrecoverable — this
is a feature, not a bug. There is no "reset password" because that
would require a backdoor.
"""

import os
import secrets
import string

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"PHV1"          # 4-byte file format marker
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32              # AES-256

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1


class VaultCryptoError(Exception):
    """Raised when decryption fails — wrong password OR corrupted/tampered file."""
    pass


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_LEN)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the master password using Scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM under a fresh random nonce.
    Returns: nonce (12 bytes) || ciphertext+tag
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext


def decrypt_blob(key: bytes, nonce_and_ciphertext: bytes) -> bytes:
    """
    Decrypt a nonce||ciphertext blob. Raises VaultCryptoError if the
    password is wrong OR the data has been tampered with — GCM's
    authentication tag makes these indistinguishable (by design).
    """
    if len(nonce_and_ciphertext) < NONCE_LEN:
        raise VaultCryptoError("Vault file is corrupted (too short).")
    nonce = nonce_and_ciphertext[:NONCE_LEN]
    ciphertext = nonce_and_ciphertext[NONCE_LEN:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        raise VaultCryptoError("Incorrect master password, or vault file is corrupted/tampered.")


def pack_vault_file(salt: bytes, encrypted_blob: bytes) -> bytes:
    """File layout: MAGIC(4) || salt(16) || nonce+ciphertext(rest)"""
    return MAGIC + salt + encrypted_blob


def unpack_vault_file(data: bytes):
    """Returns (salt, encrypted_blob). Raises VaultCryptoError on bad format."""
    if len(data) < len(MAGIC) + SALT_LEN + NONCE_LEN:
        raise VaultCryptoError("Vault file is too small / invalid format.")
    if data[:len(MAGIC)] != MAGIC:
        raise VaultCryptoError("Not a PhantomVault file (bad magic header).")
    salt = data[len(MAGIC):len(MAGIC) + SALT_LEN]
    encrypted_blob = data[len(MAGIC) + SALT_LEN:]
    return salt, encrypted_blob


# ════════════════════════════════════════════════════════════════
#  PASSWORD GENERATOR + STRENGTH ESTIMATOR
# ════════════════════════════════════════════════════════════════

AMBIGUOUS_CHARS = "Il1O0|"


def generate_password(length=20, use_upper=True, use_lower=True,
                      use_digits=True, use_symbols=True, avoid_ambiguous=True):
    """Cryptographically secure password generator using secrets module."""
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?/")

    if not pools:
        pools = [string.ascii_letters + string.digits]

    alphabet = "".join(pools)
    if avoid_ambiguous:
        alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS_CHARS)

    length = max(8, min(128, int(length)))

    # Guarantee at least one char from each selected pool for predictable strength
    password_chars = []
    for pool in pools:
        cleaned = "".join(c for c in pool if not avoid_ambiguous or c not in AMBIGUOUS_CHARS)
        if cleaned:
            password_chars.append(secrets.choice(cleaned))

    remaining = length - len(password_chars)
    password_chars += [secrets.choice(alphabet) for _ in range(max(0, remaining))]

    # Shuffle securely (Fisher-Yates using secrets.randbelow)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars[:length])


def estimate_strength(password: str) -> dict:
    """
    Lightweight entropy-based strength estimate (not a replacement for
    zxcvbn, but needs zero dependencies and works fully offline).
    """
    if not password:
        return {"score": 0, "label": "EMPTY", "entropy_bits": 0}

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(not c.isalnum() for c in password):
        pool_size += 32

    import math
    entropy_bits = len(password) * math.log2(max(pool_size, 1))

    # Penalize obvious patterns
    penalty = 0
    lower = password.lower()
    common_patterns = ["password", "123456", "qwerty", "letmein", "admin", "welcome"]
    if any(p in lower for p in common_patterns):
        penalty += 25
    if len(set(password)) < len(password) * 0.5:  # lots of repeated chars
        penalty += 10

    score = max(0, min(100, int(entropy_bits) - penalty))

    if score >= 80:
        label = "VERY STRONG"
    elif score >= 60:
        label = "STRONG"
    elif score >= 40:
        label = "MODERATE"
    elif score >= 20:
        label = "WEAK"
    else:
        label = "VERY WEAK"

    return {"score": score, "label": label, "entropy_bits": round(entropy_bits, 1)}
