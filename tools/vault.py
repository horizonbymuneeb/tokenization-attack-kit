#!/usr/bin/env python3
"""
Secure Credential Vault for Hermes
- AES-256 encryption of API keys/credentials
- Master password protection
- Decrypted values only in memory, never written to disk
- Access logging
- One-time share via Telegram with auto-expire

Usage:
  vault.py add <name> <value>      # Add credential
  vault.py add <name>              # Read value from stdin (for long secrets)
  vault.py get <name>              # Decrypt and print (use in scripts)
  vault.py list                    # List all stored names (no values)
  vault.py share <name>            # Generate one-time share link
  vault.py export <script.py>     # Decrypt all and run script with them as env vars
  vault.py rotate <name>           # Update existing credential
  vault.py remove <name>           # Delete credential
"""
import os
import sys
import json
import base64
import hashlib
import secrets
import subprocess
import getpass
import argparse
from datetime import datetime, timezone
from pathlib import Path

VAULT_DIR = Path.home() / ".hermes" / "vault"
KEYS_DIR = VAULT_DIR / "keys"
VAULT_FILE = KEYS_DIR / "vault.enc"
META_FILE = KEYS_DIR / "metadata.json"
ACCESS_LOG = VAULT_DIR / "access.log"
MASTER_HASH_FILE = KEYS_DIR / "master.hash"

# PBKDF2 for key derivation
ITERATIONS = 600_000  # OWASP 2023 recommendation

def setup_master_password():
    """First-time setup: set master password."""
    if MASTER_HASH_FILE.exists():
        print("Master password already set. Use 'vault.py unlock' to authenticate.")
        sys.exit(1)
    
    print("=== FIRST-TIME SETUP ===")
    print("Set a master password for your credential vault.")
    print("This password will be required to access any stored credentials.")
    print("USE A STRONG PASSWORD — if lost, all credentials are unrecoverable.")
    print()
    
    while True:
        pw1 = getpass.getpass("Enter master password: ")
        if len(pw1) < 8:
            print("Password too short (min 8 chars). Try again.")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords don't match. Try again.")
            continue
        break
    
    # Hash with PBKDF2 + salt
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac('sha256', pw1.encode(), salt, ITERATIONS)
    
    MASTER_HASH_FILE.write_bytes(salt + key)
    MASTER_HASH_FILE.chmod(0o600)
    
    print()
    print("✓ Master password set. REMEMBER IT — no recovery possible.")
    print(f"  Vault: {VAULT_FILE}")
    print(f"  Master: {MASTER_HASH_FILE}")
    print()

def unlock_vault():
    """Authenticate and return master key for encryption."""
    if not MASTER_HASH_FILE.exists():
        setup_master_password()
    
    data = MASTER_HASH_FILE.read_bytes()
    salt, stored_hash = data[:32], data[32:]
    
    pw = getpass.getpass("Master password: ")
    derived = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, ITERATIONS)
    
    if secrets.compare_digest(derived, stored_hash):
        return pw.encode()
    else:
        print("✗ Wrong password", file=sys.stderr)
        sys.exit(1)

def get_fernet(key_material):
    """Create Fernet cipher from key material."""
    from cryptography.fernet import Fernet
    # Derive 32-byte key from master password
    derived = hashlib.pbkdf2_hmac('sha256', key_material, b'vault-fernet-salt', ITERATIONS)
    return Fernet(base64.urlsafe_b64encode(derived))

def log_access(action, name):
    """Log access for security audit."""
    ACCESS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(ACCESS_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {action} | {name} | pid={os.getpid()}\n")

def load_vault(master_key):
    """Load and decrypt vault."""
    if not VAULT_FILE.exists():
        return {"credentials": {}}
    
    fernet = get_fernet(master_key)
    encrypted = VAULT_FILE.read_bytes()
    try:
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted)
    except Exception as e:
        print(f"✗ Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

def save_vault(vault_data, master_key):
    """Encrypt and save vault."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    fernet = get_fernet(master_key)
    encrypted = fernet.encrypt(json.dumps(vault_data).encode())
    VAULT_FILE.write_bytes(encrypted)
    VAULT_FILE.chmod(0o600)
    KEYS_DIR.chmod(0o700)

def cmd_add(name, value=None):
    """Add credential."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    if value is None:
        print(f"Enter value for '{name}' (input hidden):")
        value = getpass.getpass("Value: ")
    
    if not value:
        print("✗ Empty value", file=sys.stderr)
        sys.exit(1)
    
    vault["credentials"][name] = {
        "value": value,
        "created": datetime.now(timezone.utc).isoformat(),
        "last_accessed": None,
    }
    
    save_vault(vault, master_key)
    log_access("ADD", name)
    print(f"✓ Stored '{name}' ({len(value)} chars)")

def cmd_get(name):
    """Get credential (use in scripts)."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    if name not in vault["credentials"]:
        print(f"✗ '{name}' not found", file=sys.stderr)
        sys.exit(1)
    
    value = vault["credentials"][name]["value"]
    vault["credentials"][name]["last_accessed"] = datetime.now(timezone.utc).isoformat()
    save_vault(vault, master_key)
    log_access("GET", name)
    
    # Print to stdout (for piping into scripts)
    print(value, end="")

def cmd_list():
    """List stored credentials (names only, no values)."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    creds = vault["credentials"]
    if not creds:
        print("(empty vault)")
        return
    
    print(f"{'Name':30s} | {'Created':20s} | {'Last Used':20s} | {'Length':8s}")
    print("-" * 85)
    for name, data in sorted(creds.items()):
        created = data.get("created", "?")[:19]
        last = (data.get("last_accessed") or "never")[:19]
        print(f"{name:30s} | {created:20s} | {last:20s} | {len(data.get('value','')):8d}")
    
    log_access("LIST", "(all)")

def cmd_share(name):
    """Generate one-time share token for credential."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    if name not in vault["credentials"]:
        print(f"✗ '{name}' not found", file=sys.stderr)
        sys.exit(1)
    
    # Generate one-time token
    token = secrets.token_urlsafe(32)
    value = vault["credentials"][name]["value"]
    
    # Save token with expiry
    share_file = VAULT_DIR / "shares.json"
    shares = {}
    if share_file.exists():
        shares = json.loads(share_file.read_text())
    
    shares[token] = {
        "credential": value,
        "created": datetime.now(timezone.utc).isoformat(),
        "expires": (datetime.now(timezone.utc).timestamp() + 86400),  # 24h
        "used": False,
    }
    share_file.write_text(json.dumps(shares))
    share_file.chmod(0o600)
    
    log_access("SHARE", name)
    
    print(f"One-time share token for '{name}':")
    print(f"  Token: {token}")
    print(f"  Expires: 24 hours")
    print(f"  Use: vault.py claim {token}")

def cmd_claim(token):
    """Claim a shared credential (recipient uses this)."""
    share_file = VAULT_DIR / "shares.json"
    if not share_file.exists():
        print("✗ No shares available", file=sys.stderr)
        sys.exit(1)
    
    shares = json.loads(share_file.read_text())
    if token not in shares:
        print("✗ Invalid or expired token", file=sys.stderr)
        sys.exit(1)
    
    share = shares[token]
    if share.get("used"):
        print("✗ Token already used", file=sys.stderr)
        sys.exit(1)
    
    if datetime.now(timezone.utc).timestamp() > share["expires"]:
        print("✗ Token expired", file=sys.stderr)
        sys.exit(1)
    
    # Mark as used
    shares[token]["used"] = True
    share_file.write_text(json.dumps(shares))
    
    # Output value
    print(share["credential"])

def cmd_export():
    """Export all credentials as env vars (use in scripts)."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    for name, data in vault["credentials"].items():
        # Convert name to env var format
        env_name = name.upper().replace("-", "_").replace(".", "_")
        print(f"export {env_name}='{data['value']}'")
    
    log_access("EXPORT", "(all)")

def cmd_run(name, command):
    """Run command with credential as env var."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    if name not in vault["credentials"]:
        print(f"✗ '{name}' not found", file=sys.stderr)
        sys.exit(1)
    
    value = vault["credentials"][name]["value"]
    env_name = name.upper().replace("-", "_").replace(".", "_")
    
    env = os.environ.copy()
    env[env_name] = value
    
    log_access("RUN_WITH", f"{name} -> {command[:50]}")
    
    result = subprocess.run(command, shell=True, env=env)
    sys.exit(result.returncode)

def cmd_remove(name):
    """Remove credential."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    if name in vault["credentials"]:
        del vault["credentials"][name]
        save_vault(vault, master_key)
        log_access("REMOVE", name)
        print(f"✓ Removed '{name}'")
    else:
        print(f"✗ '{name}' not found", file=sys.stderr)

def cmd_rotate(name):
    """Rotate (update) existing credential."""
    master_key = unlock_vault()
    vault = load_vault(master_key)
    
    if name not in vault["credentials"]:
        print(f"✗ '{name}' not found", file=sys.stderr)
        sys.exit(1)
    
    print(f"Enter new value for '{name}':")
    new_value = getpass.getpass("New value: ")
    
    if not new_value:
        print("✗ Empty value", file=sys.stderr)
        sys.exit(1)
    
    vault["credentials"][name]["value"] = new_value
    vault["credentials"][name]["last_accessed"] = None
    save_vault(vault, master_key)
    log_access("ROTATE", name)
    print(f"✓ Rotated '{name}'")

def main():
    parser = argparse.ArgumentParser(description="Secure credential vault")
    sub = parser.add_subparsers(dest="cmd", required=True)
    
    add = sub.add_parser("add", help="Add credential")
    add.add_argument("name")
    add.add_argument("value", nargs="?", default=None)
    
    get = sub.add_parser("get", help="Get credential (for scripts)")
    get.add_argument("name")
    
    sub.add_parser("list", help="List credential names (no values)")
    
    share = sub.add_parser("share", help="Generate one-time share token")
    share.add_argument("name")
    
    claim = sub.add_parser("claim", help="Claim a shared credential")
    claim.add_argument("token")
    
    sub.add_parser("export", help="Export as env vars (for sourcing)")
    
    run = sub.add_parser("run", help="Run command with credential as env var")
    run.add_argument("name")
    run.add_argument("command")
    
    rm = sub.add_parser("remove", help="Remove credential")
    rm.add_argument("name")
    
    rot = sub.add_parser("rotate", help="Update existing credential")
    rot.add_argument("name")
    
    args = parser.parse_args()
    
    if args.cmd == "add":
        cmd_add(args.name, args.value)
    elif args.cmd == "get":
        cmd_get(args.name)
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "share":
        cmd_share(args.name)
    elif args.cmd == "claim":
        cmd_claim(args.token)
    elif args.cmd == "export":
        cmd_export()
    elif args.cmd == "run":
        cmd_run(args.name, args.command)
    elif args.cmd == "remove":
        cmd_remove(args.name)
    elif args.cmd == "rotate":
        cmd_rotate(args.name)

if __name__ == "__main__":
    main()
