#!/usr/bin/env python3
"""
PhantomVault — Encrypted Password Manager
═══════════════════════════════════════════════════════════════
AES-256-GCM + Scrypt KDF. Local-only. Your master password never
touches disk in any form. Run it on your own machine, not exposed
to the network.
"""

import os
import secrets

from flask import Flask, render_template, request, jsonify, make_response

from modules import crypto_vault, vault_store, session_manager
from modules.crypto_vault import VaultCryptoError

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

SESSION_COOKIE_NAME = "pv_session"


# ════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════

def _get_token():
    return request.cookies.get(SESSION_COOKIE_NAME)


def _require_unlocked():
    """Returns the session dict if unlocked, else None."""
    token = _get_token()
    if not token:
        return None
    return session_manager.get_session(token)


def _set_session_cookie(resp, token):
    resp.set_cookie(SESSION_COOKIE_NAME, token, httponly=True, samesite="Lax")
    return resp


# ════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    sess = _require_unlocked()
    if sess:
        return render_template("dashboard.html")
    return render_template("lock.html", vault_exists=vault_store.vault_exists())


# ════════════════════════════════════════════════════════════════
#  AUTH / VAULT LIFECYCLE
# ════════════════════════════════════════════════════════════════

@app.route("/api/vault/status")
def api_status():
    sess = _require_unlocked()
    token = _get_token()
    return jsonify({
        "vault_exists": vault_store.vault_exists(),
        "unlocked": sess is not None,
        "idle_seconds_remaining": session_manager.seconds_until_idle_lock(token) if sess else None,
    })


@app.route("/api/vault/create", methods=["POST"])
def api_create():
    data = request.get_json(force=True)
    master_password = data.get("master_password", "")
    confirm = data.get("confirm_password", "")

    if master_password != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    try:
        key = vault_store.create_vault(master_password)
    except FileExistsError as e:
        return jsonify({"error": str(e)}), 409
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    _, vault = vault_store.unlock_vault(master_password)  # re-read to get canonical structure
    token = secrets.token_hex(32)
    session_manager.create_session(token, key, vault)

    resp = make_response(jsonify({"status": "created", "unlocked": True}))
    return _set_session_cookie(resp, token)


@app.route("/api/vault/unlock", methods=["POST"])
def api_unlock():
    data = request.get_json(force=True)
    master_password = data.get("master_password", "")

    if not vault_store.vault_exists():
        return jsonify({"error": "No vault exists yet. Create one first."}), 404

    try:
        key, vault = vault_store.unlock_vault(master_password)
    except VaultCryptoError as e:
        return jsonify({"error": str(e)}), 401

    token = secrets.token_hex(32)
    session_manager.create_session(token, key, vault)

    resp = make_response(jsonify({"status": "unlocked"}))
    return _set_session_cookie(resp, token)


@app.route("/api/vault/lock", methods=["POST"])
def api_lock():
    token = _get_token()
    if token:
        session_manager.destroy_session(token)
    resp = make_response(jsonify({"status": "locked"}))
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


@app.route("/api/vault/change-master-password", methods=["POST"])
def api_change_master():
    sess = _require_unlocked()
    if not sess:
        return jsonify({"error": "Vault is locked."}), 401

    data = request.get_json(force=True)
    new_password = data.get("new_master_password", "")
    confirm = data.get("confirm_password", "")
    if new_password != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    try:
        new_key = vault_store.change_master_password(sess["key"], sess["vault"], new_password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    sess["key"] = new_key  # update in-memory session with new key
    return jsonify({"status": "master password changed"})


# ════════════════════════════════════════════════════════════════
#  ENTRY CRUD  (all require an unlocked vault)
# ════════════════════════════════════════════════════════════════

@app.route("/api/vault/entries")
def api_list_entries():
    sess = _require_unlocked()
    if not sess:
        return jsonify({"error": "Vault is locked."}), 401

    query = request.args.get("q", "")
    entries = vault_store.search_entries(sess["vault"], query) if query else vault_store.list_entries(sess["vault"])
    return jsonify({"entries": entries})


@app.route("/api/vault/entries/<entry_id>/reveal")
def api_reveal_entry(entry_id):
    """Returns the password for ONE entry — only called on explicit user action (reveal/copy)."""
    sess = _require_unlocked()
    if not sess:
        return jsonify({"error": "Vault is locked."}), 401

    entry = vault_store.get_entry(sess["vault"], entry_id)
    if not entry:
        return jsonify({"error": "Entry not found."}), 404
    return jsonify({"password": entry["password"]})


@app.route("/api/vault/entries", methods=["POST"])
def api_add_entry():
    sess = _require_unlocked()
    if not sess:
        return jsonify({"error": "Vault is locked."}), 401

    data = request.get_json(force=True)
    try:
        entry = vault_store.add_entry(
            sess["vault"], data.get("site", ""), data.get("username", ""),
            data.get("password", ""), data.get("notes", ""),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    vault_store.save_vault(sess["key"], sess["vault"])
    return jsonify({"status": "added", "id": entry["id"]})


@app.route("/api/vault/entries/<entry_id>", methods=["PUT"])
def api_update_entry(entry_id):
    sess = _require_unlocked()
    if not sess:
        return jsonify({"error": "Vault is locked."}), 401

    data = request.get_json(force=True)
    try:
        vault_store.update_entry(
            sess["vault"], entry_id,
            site=data.get("site"), username=data.get("username"),
            password=data.get("password"), notes=data.get("notes"),
        )
    except KeyError as e:
        return jsonify({"error": str(e)}), 404

    vault_store.save_vault(sess["key"], sess["vault"])
    return jsonify({"status": "updated"})


@app.route("/api/vault/entries/<entry_id>", methods=["DELETE"])
def api_delete_entry(entry_id):
    sess = _require_unlocked()
    if not sess:
        return jsonify({"error": "Vault is locked."}), 401

    found = vault_store.delete_entry(sess["vault"], entry_id)
    if not found:
        return jsonify({"error": "Entry not found."}), 404

    vault_store.save_vault(sess["key"], sess["vault"])
    return jsonify({"status": "deleted"})


# ════════════════════════════════════════════════════════════════
#  PASSWORD GENERATOR / STRENGTH  (no vault access needed)
# ════════════════════════════════════════════════════════════════

@app.route("/api/generate-password", methods=["POST"])
def api_generate_password():
    data = request.get_json(force=True) or {}
    pw = crypto_vault.generate_password(
        length=data.get("length", 20),
        use_upper=data.get("use_upper", True),
        use_lower=data.get("use_lower", True),
        use_digits=data.get("use_digits", True),
        use_symbols=data.get("use_symbols", True),
        avoid_ambiguous=data.get("avoid_ambiguous", True),
    )
    return jsonify({"password": pw, "strength": crypto_vault.estimate_strength(pw)})


@app.route("/api/check-strength", methods=["POST"])
def api_check_strength():
    data = request.get_json(force=True) or {}
    return jsonify(crypto_vault.estimate_strength(data.get("password", "")))


if __name__ == "__main__":
    print(r"""
   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
        V A U L T  —  AES-256-GCM Encrypted Password Manager
        Running at http://127.0.0.1:5050
        ⚠  Local tool only — do not expose this to the network.
    """)
    app.run(debug=True, host="127.0.0.1", port=5050)
