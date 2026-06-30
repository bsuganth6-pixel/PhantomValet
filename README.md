# 🔐 PhantomVault

**An AES-256-GCM encrypted password manager.** Local-only, single master
password, clipboard auto-clear, secure password generator. Built as Day 1
of the Phantom Security toolkit.

---

## How the security actually works

| Layer | What's used | Why |
|---|---|---|
| Key derivation | **Scrypt** (N=2¹⁴, r=8, p=1) | Memory-hard — far more resistant to GPU/ASIC brute-force than plain PBKDF2 |
| Encryption | **AES-256-GCM** | Authenticated encryption — tampering with the file causes decryption to fail loudly, not silently return garbage |
| Salt | 16 random bytes, generated once at vault creation | Prevents rainbow-table attacks (salts aren't secret, they're stored in the file header) |
| Nonce | 12 random bytes, **fresh on every save** | Critical for GCM security — verified by automated test (`test 4` below) |
| Master password | **Never stored, anywhere, in any form** | If you forget it, the vault is cryptographically unrecoverable. This is intentional — there is no backdoor. |

I ran 7 automated tests against the crypto core before shipping this, including:
- Encrypt → decrypt roundtrip integrity
- Wrong password correctly rejected
- **Tampered ciphertext correctly rejected** (GCM auth tag catches bit-flipping)
- Same plaintext encrypted twice produces different ciphertext (nonce uniqueness)
- Full HTTP-level test: create vault → lock → wrong password rejected → correct password works → data survives the cycle
- Change-master-password flow: old password rejected afterward, new password works

---

## Features

- 🔒 **Local-only** — nothing ever touches the network. Your vault lives in `vault_data/vault.dat` on your machine.
- 📋 **Clipboard auto-clear** — copied passwords wipe themselves from the clipboard after 20 seconds
- 👁️ **Auto-hide reveal** — shown passwords re-hide after 15 seconds (shoulder-surfing protection)
- 🎲 **Password generator** — cryptographically secure (`secrets` module), configurable length/charset, avoids ambiguous characters (`I`, `l`, `1`, `O`, `0`)
- 📊 **Strength meter** — entropy-based, live feedback while typing
- ⏱️ **Idle auto-lock** — vault auto-locks after 5 minutes of inactivity, with a live countdown in the header
- 🔑 **Change master password** — re-encrypts the entire vault under a new key without losing data
- 🔍 **Search** — instant filter by site or username

---

## Setup

```bash
pip install -r requirements.txt
python3 app.py
```

Open **http://127.0.0.1:5050**. First run will prompt you to create a vault with a master password.

> ⚠️ **This is a local single-user tool.** Don't expose it to a network (don't run with `host="0.0.0.0"` and don't deploy it publicly) — there's no multi-user auth, rate-limiting on unlock attempts, or HTTPS built in.

---

## Project Structure

```
phantomvault/
├── app.py                       ← Flask routes
├── requirements.txt
├── .gitignore                   ← excludes your actual vault.dat from git!
├── modules/
│   ├── crypto_vault.py          ← AES-256-GCM + Scrypt KDF + password generator
│   ├── vault_store.py           ← encrypted file I/O + entry CRUD
│   └── session_manager.py       ← in-memory key storage + idle auto-lock
├── templates/
│   ├── lock.html                ← create/unlock screen
│   └── dashboard.html           ← entry list + modals
├── static/
│   ├── css/style.css
│   └── js/
│       ├── app.js               ← toasts, clipboard auto-clear
│       ├── dashboard.js         ← entry CRUD, generator, idle countdown
│       └── matrix.js
└── vault_data/
    └── vault.dat                ← created on first run (gitignored)
```

---

## ⚠️ Honest Limitations (read before trusting this with real secrets)

This is an educational/personal project, not an audited production password
manager. Specifically:

- **No brute-force rate-limiting** on unlock attempts (yet) — someone with
  local access to your machine could script repeated unlock attempts.
  Scrypt's cost makes this slow, but it's not a substitute for rate-limiting.
- **No memory-locking** — Python doesn't give you `mlock()`-style guarantees,
  so in principle a sufficiently privileged attacker reading process memory
  could recover the key while the vault is unlocked. This is a limitation
  shared by most non-C password managers.
- **Single point of failure**: lose the vault.dat file with no backup, and
  everything in it is gone — there's no recovery mechanism by design.
- **Not independently security-audited.** Battle-tested tools like
  Bitwarden, KeePassXC, or 1Password have had years of professional
  security review. Use this to learn how password managers work, and as
  a personal/portfolio project — not as your only copy of your most
  critical credentials until you're confident in it.

**Back up `vault_data/vault.dat`** somewhere safe (encrypted USB drive,
private cloud folder) — losing this file with no backup means permanent
data loss.

---

*Day 1 of the Phantom Security toolkit. Next up: PhantomHash.*
