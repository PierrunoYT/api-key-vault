from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import keyring


APP_NAME = "apivault"
REGISTRY_FILENAME = "registry.json"
PIN_ITERATIONS = 200_000
PIN_RE = re.compile(r"^\d{4}$")


def _config_dir() -> Path:
    # Keep it dependency-free (no platformdirs).
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_NAME
        return Path.home() / "AppData" / "Roaming" / APP_NAME

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / APP_NAME
    return Path.home() / ".config" / APP_NAME


def _registry_path() -> Path:
    return _config_dir() / REGISTRY_FILENAME


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    # Best-effort permissions on POSIX.
    if os.name != "nt":
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
    tmp.replace(path)


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(txt: str) -> bytes:
    return base64.b64decode(txt.encode("ascii"))


def _normalize_pin(pin: str) -> str:
    pin = pin.strip()
    if not PIN_RE.match(pin):
        raise ValueError("PIN must be exactly 4 digits")
    return pin


def _hash_pin(pin: str, salt: bytes, *, iterations: int = PIN_ITERATIONS) -> bytes:
    pin = _normalize_pin(pin)
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, iterations)


def _verify_pin(pin: str, *, salt: bytes, expected_hash: bytes, iterations: int) -> bool:
    actual = _hash_pin(pin, salt, iterations=iterations)
    return hmac.compare_digest(actual, expected_hash)


def _as_registry(data: Any) -> dict[str, dict[str, dict[str, Any]]]:
    """Normalize/migrate registry format.

    Current schema:
      { service: { username: { updated_at, pin_salt_b64, pin_hash_b64, pin_iterations } } }

    Old schema (v0.1.0):
      { service: { username, updated_at } }
    """

    if not isinstance(data, dict):
        return {}

    # Detect old schema: service -> entry dict containing "username".
    looks_old = False
    for v in data.values():
        if isinstance(v, dict) and "username" in v:
            looks_old = True
            break

    if looks_old:
        migrated: dict[str, dict[str, dict[str, Any]]] = {}
        for service, entry in data.items():
            if not isinstance(service, str) or not isinstance(entry, dict):
                continue
            username = entry.get("username")
            if not isinstance(username, str) or not username:
                continue
            migrated.setdefault(service, {})[username] = {
                "updated_at": entry.get("updated_at"),
            }
        return migrated

    # Current schema
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for service, by_user in data.items():
        if not isinstance(service, str) or not isinstance(by_user, dict):
            continue
        users_out: dict[str, dict[str, Any]] = {}
        for username, entry in by_user.items():
            if not isinstance(username, str) or not isinstance(entry, dict):
                continue
            users_out[username] = entry
        if users_out:
            out[service] = users_out
    return out


def load_registry() -> dict[str, dict[str, dict[str, Any]]]:
    path = _registry_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return _as_registry(data)


def save_registry(reg: dict[str, dict[str, dict[str, Any]]]) -> None:
    _atomic_write_text(_registry_path(), json.dumps(reg, indent=2, sort_keys=True) + "\n")


@dataclass(frozen=True)
class StoredRef:
    service: str
    username: str


def resolve_username(service: str, username: str | None) -> str:
    if username:
        return username

    reg = load_registry()
    by_user = reg.get(service)
    if isinstance(by_user, dict) and by_user:
        if len(by_user) == 1:
            return next(iter(by_user.keys()))
        raise ValueError(
            f"Multiple usernames exist for service={service!r}; please pass --username"
        )

    # Fallback to OS username.
    return getpass.getuser()


def _require_pin_ok(service: str, username: str, pin: str) -> None:
    reg = load_registry()
    entry = reg.get(service, {}).get(username)
    if not isinstance(entry, dict):
        raise PermissionError(
            "No PIN record found for this entry. Re-run: apivault set <service> --username <u>"
        )

    salt_b64 = entry.get("pin_salt_b64")
    hash_b64 = entry.get("pin_hash_b64")
    iters = entry.get("pin_iterations")
    if not (isinstance(salt_b64, str) and isinstance(hash_b64, str) and isinstance(iters, int)):
        raise PermissionError(
            "No PIN configured for this entry. Re-run: apivault set <service> --username <u>"
        )

    salt = _b64d(salt_b64)
    expected = _b64d(hash_b64)
    if not _verify_pin(pin, salt=salt, expected_hash=expected, iterations=iters):
        raise PermissionError("Incorrect PIN")


def set_secret(service: str, username: str, secret: str, *, pin: str) -> None:
    pin = _normalize_pin(pin)
    keyring.set_password(service, username, secret)

    salt = secrets.token_bytes(16)
    pin_hash = _hash_pin(pin, salt, iterations=PIN_ITERATIONS)

    reg = load_registry()
    reg.setdefault(service, {})[username] = {
        "updated_at": _now_iso(),
        "pin_salt_b64": _b64e(salt),
        "pin_hash_b64": _b64e(pin_hash),
        "pin_iterations": PIN_ITERATIONS,
    }
    save_registry(reg)


def get_secret(service: str, username: str, *, pin: str) -> str:
    _require_pin_ok(service, username, pin)

    secret = keyring.get_password(service, username)
    if secret is None:
        raise KeyError(f"No secret found for service={service!r} username={username!r}")
    return secret


def delete_secret(service: str, username: str, *, pin: str) -> None:
    _require_pin_ok(service, username, pin)

    # keyring raises keyring.errors.PasswordDeleteError if not found.
    keyring.delete_password(service, username)

    reg = load_registry()
    by_user = reg.get(service)
    if isinstance(by_user, dict):
        by_user.pop(username, None)
        if not by_user:
            reg.pop(service, None)
        save_registry(reg)


def list_services() -> list[StoredRef]:
    reg = load_registry()
    out: list[StoredRef] = []
    for service, by_user in sorted(reg.items(), key=lambda kv: kv[0]):
        if not isinstance(by_user, dict):
            continue
        for username in sorted(by_user.keys()):
            if isinstance(username, str) and username:
                out.append(StoredRef(service=service, username=username))
    return out


def doctor_info() -> dict[str, Any]:
    kr = keyring.get_keyring()
    return {
        "config_dir": str(_config_dir()),
        "registry_path": str(_registry_path()),
        "keyring": {
            "type": type(kr).__name__,
            "repr": repr(kr),
        },
    }
