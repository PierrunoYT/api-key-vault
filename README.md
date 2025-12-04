# apivault

A tiny Python CLI that stores API keys/secrets in your **OS keychain** (macOS Keychain, Windows Credential Manager, etc.) via the `keyring` library.

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

## Usage

### Save a key

```bash
apivault set openai
# You’ll be prompted to paste the secret (input hidden)
```

By default, `set` uses `--username default`. The `username` here is **not your login** — it’s just a label/key name inside the OS keychain so you can store *multiple* secrets under the same service if you want (e.g. `--username personal` vs `--username work`).

You will also be prompted for a **4-digit PIN**. This PIN is required later for `get`/`delete`.
The PIN is stored locally only as a **salted hash** (PBKDF2), not in plaintext.

### Read a key

```bash
apivault get openai
```

### Delete a key

```bash
apivault delete openai
```

### List what you’ve stored (registry)

```bash
apivault list
```

### Debug / diagnostics

```bash
apivault doctor
```

## Notes

- Secrets are stored in your OS keychain; only a small JSON registry is stored on disk so the CLI can list services.
- Printing a secret to stdout is inherently risky (shell history, scrollback, etc.). Use `get` carefully.
