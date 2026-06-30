#!/usr/bin/env python3
"""
PhantomVault CLI — Terminal Password Manager
═══════════════════════════════════════════════════════════════
Same AES-256-GCM encrypted vault, same modules, as the web app —
just a terminal front-end instead of Flask. Pick whichever you
prefer; they read/write the exact same vault_data/vault.dat file,
so you can freely switch between the CLI and the browser UI.

USAGE
  python3 cli.py init                          Create a new vault
  python3 cli.py list                          List all entries (redacted)
  python3 cli.py search <query>                Search by site/username
  python3 cli.py add <site>                    Add a new entry (prompts for details)
  python3 cli.py show <site-or-id>             Reveal one entry's password
  python3 cli.py edit <site-or-id>             Edit an entry
  python3 cli.py delete <site-or-id>           Delete an entry
  python3 cli.py generate                      Generate a password
  python3 cli.py passwd                        Change your master password
  python3 cli.py --help                        Full option list
"""

import os
import sys
import time
import getpass
import argparse
import subprocess
import shutil

from modules import crypto_vault, vault_store
from modules.crypto_vault import VaultCryptoError

# ── ANSI colors (disabled automatically if not a real terminal) ──
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
def _c(code): return code if _USE_COLOR else ""
RESET   = _c("\033[0m")
BOLD    = _c("\033[1m")
DIM     = _c("\033[2m")
RED     = _c("\033[91m")
GREEN   = _c("\033[92m")
YELLOW  = _c("\033[93m")
CYAN    = _c("\033[96m")
VIOLET  = _c("\033[95m")


def banner():
    print(f"""{CYAN}{BOLD}
   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
   {DIM}V A U L T   C L I  —  AES-256-GCM Encrypted Password Manager{RESET}
""")


def err(msg):
    print(f"{RED}✗ {msg}{RESET}", file=sys.stderr)


def ok(msg):
    print(f"{GREEN}✓ {msg}{RESET}")


def info(msg):
    print(f"{CYAN}ℹ {msg}{RESET}")


# ════════════════════════════════════════════════════════════════
#  PASSWORD INPUT — secure by default, scriptable when needed
# ════════════════════════════════════════════════════════════════

def prompt_master_password(args, prompt="Master password: "):
    """
    Resolution order (for the CURRENT/unlock password):
      1. --master-password flag       (visible in shell history — testing/CI only)
      2. PHANTOMVAULT_MASTER_PASSWORD env var
      3. Interactive hidden prompt (getpass) if stdin is a TTY
      4. Plain stdin line (for piping in non-interactive contexts)
    """
    if getattr(args, "master_password", None):
        print(f"{YELLOW}⚠ Warning: --master-password is visible in shell history. "
              f"Prefer the interactive prompt or env var.{RESET}", file=sys.stderr)
        return args.master_password
    if os.environ.get("PHANTOMVAULT_MASTER_PASSWORD"):
        return os.environ["PHANTOMVAULT_MASTER_PASSWORD"]
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    line = sys.stdin.readline()
    return line.rstrip("\n")


def prompt_new_password(args, prompt="New password: "):
    """
    Resolution order for a NEW password (used by `init` and `passwd`).
    Deliberately does NOT fall back to PHANTOMVAULT_MASTER_PASSWORD — that
    env var holds the EXISTING/unlock password. Conflating the two would
    mean `passwd` silently "changes" the password to the same value it
    already had, which is a correctness bug, not just a testing nuisance.
      1. --new-master-password flag   (visible in shell history — testing/CI only)
      2. PHANTOMVAULT_NEW_MASTER_PASSWORD env var
      3. Interactive hidden prompt (getpass) if stdin is a TTY
      4. Plain stdin line (for piping in non-interactive contexts)
    """
    if getattr(args, "new_master_password", None):
        print(f"{YELLOW}⚠ Warning: --new-master-password is visible in shell history.{RESET}", file=sys.stderr)
        return args.new_master_password
    if os.environ.get("PHANTOMVAULT_NEW_MASTER_PASSWORD"):
        return os.environ["PHANTOMVAULT_NEW_MASTER_PASSWORD"]
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    line = sys.stdin.readline()
    return line.rstrip("\n")


def unlock_or_exit(args):
    """Prompts for the master password and unlocks the vault, or exits with an error."""
    if not vault_store.vault_exists():
        err("No vault found. Run: python3 cli.py init")
        sys.exit(1)
    password = prompt_master_password(args)
    try:
        key, vault = vault_store.unlock_vault(password)
    except VaultCryptoError as e:
        err(str(e))
        sys.exit(1)
    return key, vault


def resolve_entry(vault, site_or_id):
    """Find an entry by exact ID, exact site name (case-insensitive), or unique partial match."""
    for e in vault["entries"]:
        if e["id"] == site_or_id:
            return e
    exact = [e for e in vault["entries"] if e["site"].lower() == site_or_id.lower()]
    if len(exact) == 1:
        return exact[0]
    partial = [e for e in vault["entries"] if site_or_id.lower() in e["site"].lower()]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        err(f"Multiple entries match '{site_or_id}': " + ", ".join(e["site"] for e in partial))
        err("Use the exact site name or the entry ID (see: list --ids).")
        sys.exit(1)
    return None


# ════════════════════════════════════════════════════════════════
#  CLIPBOARD (best-effort, cross-platform, with auto-clear)
# ════════════════════════════════════════════════════════════════

def _clipboard_copy(text):
    """Try pyperclip first, then platform-native tools. Returns True on success."""
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass

    candidates = []
    if sys.platform == "darwin":
        candidates = [["pbcopy"]]
    elif sys.platform == "win32":
        candidates = [["clip"]]
    else:
        candidates = [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"], ["wl-copy"]]

    for cmd in candidates:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), check=True)
                return True
            except Exception:
                continue
    return False


def _clipboard_clear():
    try:
        import pyperclip
        pyperclip.copy("")
        return
    except Exception:
        pass
    if sys.platform == "darwin" and shutil.which("pbcopy"):
        subprocess.run(["pbcopy"], input=b"")
    elif sys.platform == "win32" and shutil.which("clip"):
        subprocess.run(["clip"], input=b"")
    elif shutil.which("xclip"):
        subprocess.run(["xclip", "-selection", "clipboard"], input=b"")
    elif shutil.which("xsel"):
        subprocess.run(["xsel", "--clipboard", "--input"], input=b"")


def copy_with_autoclear(text, label="Password", seconds=20):
    copied = _clipboard_copy(text)
    if not copied:
        print(f"{YELLOW}⚠ Clipboard not available in this environment — printing instead:{RESET}")
        print(f"  {GREEN}{text}{RESET}")
        return

    ok(f"{label} copied to clipboard.")
    try:
        for remaining in range(seconds, 0, -1):
            print(f"\r{DIM}  Clipboard clears in {remaining:>2}s — Ctrl+C to skip wait...{RESET}",
                  end="", flush=True)
            time.sleep(1)
        print()
    except KeyboardInterrupt:
        print()
        info("Skipped wait — clipboard will NOT auto-clear. Clear it manually if needed.")
        return
    _clipboard_clear()
    ok("Clipboard cleared.")


# ════════════════════════════════════════════════════════════════
#  COMMANDS
# ════════════════════════════════════════════════════════════════

def cmd_init(args):
    if vault_store.vault_exists():
        err(f"A vault already exists at {vault_store.VAULT_PATH}")
        sys.exit(1)

    print(f"{BOLD}Create a new PhantomVault{RESET}")
    print(f"{DIM}There is no password recovery. If you forget your master password,\n"
          f"the vault is cryptographically unrecoverable — by design.{RESET}\n")

    # If supplied non-interactively (env var or flag), skip confirmation —
    # can't make a typo when pasting/scripting.
    from_env = bool(os.environ.get("PHANTOMVAULT_NEW_MASTER_PASSWORD")) or bool(getattr(args, "new_master_password", None))
    password = prompt_new_password(args, "New master password: ")

    if from_env:
        confirm = password  # no confirmation needed, already non-interactive
    elif sys.stdin.isatty():
        confirm = getpass.getpass("Confirm master password: ")
    else:
        confirm = sys.stdin.readline().rstrip("\n")

    if password != confirm:
        err("Passwords do not match.")
        sys.exit(1)
    if len(password) < 8:
        err("Master password must be at least 8 characters.")
        sys.exit(1)

    strength = crypto_vault.estimate_strength(password)
    info(f"Master password strength: {strength['label']} (score {strength['score']}/100)")
    if strength["score"] < 40 and sys.stdin.isatty():
        answer = input(f"{YELLOW}This is a weak master password. Continue anyway? [y/N]: {RESET}")
        if answer.lower() != "y":
            print("Cancelled.")
            sys.exit(0)

    vault_store.create_vault(password)
    ok(f"Vault created at {vault_store.VAULT_PATH}")


def cmd_list(args):
    key, vault = unlock_or_exit(args)
    entries = vault_store.search_entries(vault, args.query) if getattr(args, "query", None) else vault_store.list_entries(vault)

    if not entries:
        info("No entries found.")
        return

    print(f"\n{BOLD}{'SITE':<24}{'USERNAME':<28}{'UPDATED':<20}{'ID' if args.ids else ''}{RESET}")
    print(DIM + "─" * (90 if args.ids else 70) + RESET)
    for e in entries:
        updated = time.strftime("%Y-%m-%d %H:%M", time.localtime(e["updated"])) if e.get("updated") else "—"
        id_col = f"{DIM}{e['id']}{RESET}" if args.ids else ""
        print(f"{CYAN}{e['site']:<24}{RESET}{e['username']:<28}{DIM}{updated:<20}{RESET}{id_col}")
    print(f"\n{DIM}{len(entries)} entrie(s).{RESET}")


def cmd_show(args):
    key, vault = unlock_or_exit(args)
    entry = resolve_entry(vault, args.target)
    if not entry:
        err(f"No entry found matching '{args.target}'.")
        sys.exit(1)

    print(f"\n{BOLD}{entry['site']}{RESET}")
    print(f"{DIM}Username:{RESET} {entry['username'] or '—'}")
    print(f"{DIM}Password:{RESET} {GREEN}{entry['password']}{RESET}")
    if entry.get("notes"):
        print(f"{DIM}Notes:{RESET}    {entry['notes']}")
    print()

    if args.copy:
        copy_with_autoclear(entry["password"], "Password")


def cmd_add(args):
    key, vault = unlock_or_exit(args)

    site = args.site
    username = args.username or input("Username: ")

    if args.generate:
        password = crypto_vault.generate_password(
            length=args.length, use_symbols=not args.no_symbols)
        info(f"Generated password: {GREEN}{password}{RESET}")
    elif args.password:
        password = args.password
    else:
        password = getpass.getpass("Password (input hidden): ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")

    notes = args.notes or ""

    strength = crypto_vault.estimate_strength(password)
    info(f"Password strength: {strength['label']} (score {strength['score']}/100)")

    entry = vault_store.add_entry(vault, site, username, password, notes)
    vault_store.save_vault(key, vault)
    ok(f"Added entry '{entry['site']}' (id: {entry['id']})")


def cmd_edit(args):
    key, vault = unlock_or_exit(args)
    entry = resolve_entry(vault, args.target)
    if not entry:
        err(f"No entry found matching '{args.target}'.")
        sys.exit(1)

    updates = {}
    if args.site:
        updates["site"] = args.site
    if args.username:
        updates["username"] = args.username
    if args.notes is not None:
        updates["notes"] = args.notes

    if args.generate:
        updates["password"] = crypto_vault.generate_password(length=args.length, use_symbols=not args.no_symbols)
        info(f"Generated new password: {GREEN}{updates['password']}{RESET}")
    elif args.password:
        updates["password"] = args.password

    if not updates:
        info("Nothing to update — specify --site, --username, --password, --generate, or --notes.")
        return

    vault_store.update_entry(vault, entry["id"], **updates)
    vault_store.save_vault(key, vault)
    ok(f"Updated entry '{entry['site']}'.")


def cmd_delete(args):
    key, vault = unlock_or_exit(args)
    entry = resolve_entry(vault, args.target)
    if not entry:
        err(f"No entry found matching '{args.target}'.")
        sys.exit(1)

    if not args.yes:
        confirm = input(f"Delete '{entry['site']}' ({entry['username']})? [y/N]: ")
        if confirm.lower() != "y":
            print("Cancelled.")
            return

    vault_store.delete_entry(vault, entry["id"])
    vault_store.save_vault(key, vault)
    ok(f"Deleted '{entry['site']}'.")


def cmd_generate(args):
    password = crypto_vault.generate_password(
        length=args.length,
        use_upper=not args.no_upper, use_lower=not args.no_lower,
        use_digits=not args.no_digits, use_symbols=not args.no_symbols,
        avoid_ambiguous=not args.allow_ambiguous,
    )
    strength = crypto_vault.estimate_strength(password)
    print(f"\n{BOLD}{GREEN}{password}{RESET}")
    print(f"{DIM}Strength: {strength['label']} ({strength['score']}/100, ~{strength['entropy_bits']} bits entropy){RESET}\n")

    if args.copy:
        copy_with_autoclear(password, "Generated password")


def cmd_passwd(args):
    key, vault = unlock_or_exit(args)

    print(f"\n{BOLD}Change Master Password{RESET}")
    from_env = bool(os.environ.get("PHANTOMVAULT_NEW_MASTER_PASSWORD")) or bool(getattr(args, "new_master_password", None))
    new_password = prompt_new_password(args, "New master password: ")

    if from_env:
        confirm = new_password
    elif sys.stdin.isatty():
        confirm = getpass.getpass("Confirm new master password: ")
    else:
        confirm = sys.stdin.readline().rstrip("\n")

    if new_password != confirm:
        err("Passwords do not match.")
        sys.exit(1)
    if len(new_password) < 8:
        err("New master password must be at least 8 characters.")
        sys.exit(1)

    vault_store.change_master_password(key, vault, new_password)
    ok("Master password changed. Existing entries are preserved.")


def cmd_status(args):
    exists = vault_store.vault_exists()
    print(f"\n{BOLD}PhantomVault Status{RESET}")
    print(f"{DIM}Vault file:{RESET} {vault_store.VAULT_PATH}")
    print(f"{DIM}Exists:{RESET}     {'Yes' if exists else 'No — run: python3 cli.py init'}")
    if exists:
        size = os.path.getsize(vault_store.VAULT_PATH)
        print(f"{DIM}Size:{RESET}       {size} bytes")
    print()


# ════════════════════════════════════════════════════════════════
#  ARGPARSE
# ════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        prog="cli.py",
        description="PhantomVault — AES-256-GCM encrypted password manager (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_master_pw_arg(sp):
        sp.add_argument("--master-password", help="Master password (insecure — visible in shell history; prefer prompt or env var)")

    sp = sub.add_parser("init", help="Create a new vault")
    add_master_pw_arg(sp)
    sp.add_argument("--new-master-password", default=None,
                    help="New master password (prefer PHANTOMVAULT_NEW_MASTER_PASSWORD env var)")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("list", help="List entries (passwords redacted)")
    sp.add_argument("query", nargs="?", default=None, help="Optional search filter")
    sp.add_argument("--ids", action="store_true", help="Show entry IDs")
    add_master_pw_arg(sp)
    sp.set_defaults(func=cmd_list, query=None)

    sp = sub.add_parser("search", help="Search entries by site/username")
    sp.add_argument("query")
    sp.add_argument("--ids", action="store_true")
    add_master_pw_arg(sp)
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("show", help="Reveal one entry's password")
    sp.add_argument("target", help="Site name or entry ID")
    sp.add_argument("--copy", action="store_true", help="Copy password to clipboard (auto-clears in 20s)")
    add_master_pw_arg(sp)
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("add", help="Add a new entry")
    sp.add_argument("site")
    sp.add_argument("--username", default=None)
    sp.add_argument("--password", default=None, help="Set explicitly (insecure in shell history — omit to be prompted)")
    sp.add_argument("--generate", action="store_true", help="Auto-generate a secure password")
    sp.add_argument("--length", type=int, default=20)
    sp.add_argument("--no-symbols", action="store_true")
    sp.add_argument("--notes", default=None)
    add_master_pw_arg(sp)
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("edit", help="Edit an existing entry")
    sp.add_argument("target", help="Site name or entry ID")
    sp.add_argument("--site", default=None, help="New site name")
    sp.add_argument("--username", default=None)
    sp.add_argument("--password", default=None)
    sp.add_argument("--generate", action="store_true")
    sp.add_argument("--length", type=int, default=20)
    sp.add_argument("--no-symbols", action="store_true")
    sp.add_argument("--notes", default=None)
    add_master_pw_arg(sp)
    sp.set_defaults(func=cmd_edit)

    sp = sub.add_parser("delete", help="Delete an entry")
    sp.add_argument("target", help="Site name or entry ID")
    sp.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    add_master_pw_arg(sp)
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("generate", help="Generate a password (no vault needed)")
    sp.add_argument("--length", type=int, default=20)
    sp.add_argument("--no-upper", action="store_true")
    sp.add_argument("--no-lower", action="store_true")
    sp.add_argument("--no-digits", action="store_true")
    sp.add_argument("--no-symbols", action="store_true")
    sp.add_argument("--allow-ambiguous", action="store_true", help="Allow I/l/1/O/0 (excluded by default)")
    sp.add_argument("--copy", action="store_true")
    sp.set_defaults(func=cmd_generate)

    sp = sub.add_parser("passwd", help="Change the master password")
    add_master_pw_arg(sp)
    sp.add_argument("--new-master-password", default=None,
                    help="New master password (insecure in shell history; prefer PHANTOMVAULT_NEW_MASTER_PASSWORD env var)")
    sp.set_defaults(func=cmd_passwd)

    sp = sub.add_parser("status", help="Show vault file status")
    sp.set_defaults(func=cmd_status)

    return p


def main():
    if len(sys.argv) == 1:
        banner()
        build_parser().print_help()
        return

    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print()
        info("Cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
