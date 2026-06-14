# Hermes Secure Credential Vault

## Overview

`vault` is a secure way to store and share API keys, tokens, and other credentials. All credentials are:
- Encrypted with AES-256 (Fernet) using PBKDF2-derived key
- Master password protected (600K iterations, OWASP 2023)
- Never written to disk in plain text
- Logged on every access

## Setup (One-Time)

```bash
# First time: set master password
vault add test-key test-value
# Will prompt for master password setup
```

## Adding Credentials

```bash
# Direct (visible in shell history - careful!)
vault add openai-key sk-proj-xxxxx

# Hidden input (recommended)
vault add openai-key
# (will prompt for value, input hidden)
```

## Listing Credentials

```bash
vault list
# Shows names, created date, last accessed, length
# NEVER shows values
```

## Using Credentials in Scripts

```bash
# Method 1: Pipe to command
python3 script.py <<< "$(vault get openai-key)"

# Method 2: Source as env var
eval "$(vault export)"
python3 script.py  # uses $OPENAI_KEY env var

# Method 3: Direct env var
vault run openai-key "python3 script.py"

# Method 4: Just the value (in scripts)
SECRET=$(vault get openai-key)
```

## Sharing with Me (Hermes/Telegram)

You share credentials with me via **one-time share tokens**:

1. **You** generate a token: `vault share openai-key`
2. **Token** is sent to Telegram (one-time, 24hr expiry)
3. **I** (Hermes) claim it: `vault claim <token>` 
4. **Token** is destroyed after use

The token never contains the actual key — it's a reference to a server-stored encrypted blob.

## Security Properties

| Feature | Implementation |
|---------|---------------|
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Key derivation | PBKDF2-HMAC-SHA256, 600K iterations |
| Salt | Random 32 bytes per master |
| Access logging | Every add/get/list/share logged |
| File permissions | Vault dir 700, vault file 600 |
| Token expiry | 24h, single use |
| Memory safety | Values only in memory, no swap leaks |

## Files

- `~/.hermes/vault/vault.py` - Main tool
- `~/.hermes/vault/keys/vault.enc` - Encrypted credentials
- `~/.hermes/vault/keys/master.hash` - Master password hash + salt
- `~/.hermes/vault/access.log` - All access events
- `~/.hermes/vault/shares.json` - Active share tokens

## Common Commands

```bash
vault add <name> [value]     # Add credential
vault get <name>             # Get value (for scripts)
vault list                   # List all names
vault share <name>           # Create one-time share token
vault claim <token>          # Receive a shared credential
vault export                 # Output all as export statements
vault run <name> <cmd>       # Run command with cred as env var
vault rotate <name>          # Update existing credential
vault remove <name>          # Delete credential
```

## What to Store

✓ API keys (OpenAI, Anthropic, etc.)
✓ Database passwords
✓ Webhook URLs with secrets
✓ OAuth tokens
✓ SSH private keys (path references)

✗ Don't store: master password itself, recovery codes (use 1Password/Bitwarden)
