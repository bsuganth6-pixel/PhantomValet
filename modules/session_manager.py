"""
PhantomVault — Session Manager
═══════════════════════════════════════════════════════════════
Holds the decrypted vault key + data IN SERVER MEMORY ONLY, keyed by
a random session token (never the master password itself). Enforces
idle auto-lock: if no request comes in within IDLE_TIMEOUT seconds,
the key is wiped from memory and the user must re-enter their master
password.

This is a single-user local tool (you run it on your own machine),
so a simple in-process dict is appropriate — this is NOT designed for
multi-user/networked deployment.
"""

import time
import threading

IDLE_TIMEOUT_SECONDS = 5 * 60  # auto-lock after 5 minutes of inactivity

_lock = threading.Lock()
_sessions = {}  # token -> {"key": bytes, "vault": dict, "last_active": float}


def create_session(token: str, key: bytes, vault: dict):
    with _lock:
        _sessions[token] = {"key": key, "vault": vault, "last_active": time.time()}


def touch(token: str) -> bool:
    """Update last_active. Returns False if session doesn't exist or has expired (and wipes it)."""
    with _lock:
        sess = _sessions.get(token)
        if not sess:
            return False
        if time.time() - sess["last_active"] > IDLE_TIMEOUT_SECONDS:
            del _sessions[token]
            return False
        sess["last_active"] = time.time()
        return True


def get_session(token: str):
    """Returns the session dict if valid/unexpired, else None (and wipes expired sessions)."""
    if not touch(token):
        return None
    with _lock:
        return _sessions.get(token)


def destroy_session(token: str):
    with _lock:
        _sessions.pop(token, None)


def is_unlocked(token: str) -> bool:
    return get_session(token) is not None


def seconds_until_idle_lock(token: str):
    with _lock:
        sess = _sessions.get(token)
        if not sess:
            return None
        elapsed = time.time() - sess["last_active"]
        remaining = IDLE_TIMEOUT_SECONDS - elapsed
        return max(0, round(remaining))
