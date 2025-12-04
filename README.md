# apivault

A tiny Python CLI to store API keys/secrets **locally and safely**.

- **Secret storage**: stored in your **OS keychain** (Windows Credential Manager / macOS Keychain / etc.) via the `keyring` library.
- **Extra protection**: every secret is also protected by a required **4-digit PIN**.
  - The PIN is **not** stored in plaintext.
  - Only a **salted PBKDF2 hash** is stored locally in a small registry file.

## Install (editable)

```bash
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
# source .venv/bin/activate

pip install -U pip
pip install -e .
```

## Concepts

### `service`
A name like `openai`, `github`, `stripe`, etc.

### `--username`
This is **not your login**. It’s just a label inside the keychain so you can store multiple secrets under the same `service`.

Examples:
- `--username default`
- `--username work`
- `--username personal`

If you only need one key per service, you can ignore it — `set` defaults to `--username default`.

### PIN
When you `set` a secret, you choose a **4-digit PIN**. That same PIN is required for `get` and `delete`.

## Usage

### Save a key (interactive)

```bash
apivault set openai
# Prompts for:
# - 4-digit PIN (with confirmation)
# - secret value (hidden input)
```

### Read a key (interactive)

```bash
apivault get openai
# Prompts for the 4-digit PIN
```

### Delete a key (interactive)

```bash
apivault delete openai
# Prompts for the 4-digit PIN
```

### Non-interactive examples

```bash
apivault set openai --pin 1234 --value "sk-..."
apivault get openai --pin 1234
apivault delete openai --pin 1234
```

### Store multiple secrets under one service

```bash
apivault set openai --username work
apivault set openai --username personal

apivault get openai --username work
apivault get openai --username personal
```

### List what you’ve stored (registry)

```bash
apivault list
# Prints: <service> <tab> <username>
```

### Debug / diagnostics

```bash
apivault doctor
```

## Security notes

- The **secret** lives in the OS keychain.
- The local registry file contains only metadata + a **salted hash** of your PIN.
- `get` prints the secret to stdout (use carefully: shell history, scrollback, etc.).

## Files on disk

- The registry file is stored under your config directory:
  - Windows: `%APPDATA%\apivault\registry.json`
  - macOS/Linux: `~/.config/apivault/registry.json` (or `$XDG_CONFIG_HOME/apivault/registry.json`)
