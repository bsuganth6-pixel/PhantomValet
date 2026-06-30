"""
PhantomVault — Vault Storage
═══════════════════════════════════════════════════════════════
Manages the on-disk encrypted vault file: create, unlock, save, and
CRUD operations on entries. The decrypted vault is plain Python data
that lives ONLY in server memory (never written to disk unencrypted).
"""

import os
import json
import time
import uuid

from modules.crypto_vault import (
    generate_salt, derive_key, encrypt_blob, decrypt_blob,
    pack_vault_file, unpack_vault_file, VaultCryptoError,
)

VAULT_DIR = os.environ.get("VAULT_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "vault_data"))
VAULT_PATH = os.path.join(VAULT_DIR, "vault.dat")


def vault_exists() -> bool:
    return os.path.exists(VAULT_PATH)


def create_vault(master_password: str) -> bytes:
    """
    Create a brand-new empty vault, encrypted with the given master
    password. Returns the derived key (caller keeps it in memory for
    the session — it is never persisted).
    """
    if vault_exists():
        raise FileExistsError("A vault already exists. Unlock it instead of creating a new one.")
    if not master_password or len(master_password) < 8:
        raise ValueError("Master password must be at least 8 characters.")

    os.makedirs(VAULT_DIR, exist_ok=True)
    salt = generate_salt()
    key = derive_key(master_password, salt)

    empty_vault = {"version": 1, "entries": []}
    plaintext = json.dumps(empty_vault).encode("utf-8")
    encrypted_blob = encrypt_blob(key, plaintext)

    with open(VAULT_PATH, "wb") as f:
        f.write(pack_vault_file(salt, encrypted_blob))

    return key


def unlock_vault(master_password: str):
    """
    Attempt to unlock the vault with the given master password.
    Returns (key, vault_dict) on success.
    Raises VaultCryptoError on wrong password / corrupted file.
    Raises FileNotFoundError if no vault exists yet.
    """
    if not vault_exists():
        raise FileNotFoundError("No vault found. Create one first.")

    with open(VAULT_PATH, "rb") as f:
        raw = f.read()

    salt, encrypted_blob = unpack_vault_file(raw)
    key = derive_key(master_password, salt)
    plaintext = decrypt_blob(key, encrypted_blob)  # raises VaultCryptoError if wrong password
    vault = json.loads(plaintext.decode("utf-8"))
    return key, vault


def save_vault(key: bytes, vault: dict):
    """Re-encrypt the full vault dict under the SAME key with a FRESH nonce, overwrite file."""
    with open(VAULT_PATH, "rb") as f:
        raw = f.read()
    salt, _old_blob = unpack_vault_file(raw)  # reuse the existing salt — salt never changes for a given key

    plaintext = json.dumps(vault).encode("utf-8")
    encrypted_blob = encrypt_blob(key, plaintext)

    tmp_path = VAULT_PATH + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(pack_vault_file(salt, encrypted_blob))
    os.replace(tmp_path, VAULT_PATH)  # atomic on POSIX — avoids corrupting the vault on crash mid-write


def change_master_password(key: bytes, vault: dict, new_master_password: str) -> bytes:
    """Re-derive a new key+salt and re-encrypt the whole vault under it."""
    if not new_master_password or len(new_master_password) < 8:
        raise ValueError("New master password must be at least 8 characters.")

    new_salt = generate_salt()
    new_key = derive_key(new_master_password, new_salt)
    plaintext = json.dumps(vault).encode("utf-8")
    encrypted_blob = encrypt_blob(new_key, plaintext)

    tmp_path = VAULT_PATH + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(pack_vault_file(new_salt, encrypted_blob))
    os.replace(tmp_path, VAULT_PATH)

    return new_key


# ════════════════════════════════════════════════════════════════
#  ENTRY CRUD (operates on the in-memory decrypted vault dict)
# ════════════════════════════════════════════════════════════════

def list_entries(vault: dict):
    """Returns entries with passwords REDACTED (for the list view)."""
    return [
        {
            "id": e["id"], "site": e["site"], "username": e["username"],
            "notes": e.get("notes", ""), "updated": e.get("updated"),
            "has_password": bool(e.get("password")),
        }
        for e in vault["entries"]
    ]


def get_entry(vault: dict, entry_id: str):
    """Returns the full entry INCLUDING password — only call this for a single reveal/copy action."""
    for e in vault["entries"]:
        if e["id"] == entry_id:
            return e
    return None


def add_entry(vault: dict, site: str, username: str, password: str, notes: str = ""):
    if not site:
        raise ValueError("Site name is required.")
    entry = {
        "id": uuid.uuid4().hex,
        "site": site.strip(),
        "username": username.strip(),
        "password": password,
        "notes": notes.strip(),
        "created": time.time(),
        "updated": time.time(),
    }
    vault["entries"].append(entry)
    return entry


def update_entry(vault: dict, entry_id: str, **fields):
    entry = get_entry(vault, entry_id)
    if not entry:
        raise KeyError("Entry not found.")
    for k in ("site", "username", "password", "notes"):
        if k in fields and fields[k] is not None:
            entry[k] = fields[k]
    entry["updated"] = time.time()
    return entry


def delete_entry(vault: dict, entry_id: str) -> bool:
    before = len(vault["entries"])
    vault["entries"] = [e for e in vault["entries"] if e["id"] != entry_id]
    return len(vault["entries"]) < before


def search_entries(vault: dict, query: str):
    q = query.lower().strip()
    if not q:
        return list_entries(vault)
    matches = [e for e in vault["entries"]
              if q in e["site"].lower() or q in e["username"].lower()]
    return [
        {
            "id": e["id"], "site": e["site"], "username": e["username"],
            "notes": e.get("notes", ""), "updated": e.get("updated"),
            "has_password": bool(e.get("password")),
        }
        for e in matches
    ]
