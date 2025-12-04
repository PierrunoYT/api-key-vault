from __future__ import annotations

import argparse
import json
import sys
from getpass import getpass

from .store import (
    delete_secret,
    doctor_info,
    get_secret,
    list_services,
    resolve_username,
    set_secret,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apivault",
        description="Store and retrieve API keys from your OS keychain.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_set = sub.add_parser("set", help="Save/overwrite a secret")
    p_set.add_argument("service", help="Service name (e.g. openai, github)")
    p_set.add_argument("--username", default="default", help="Keyring username label")
    p_set.add_argument(
        "--pin",
        help="4-digit PIN required to access this secret later (prompted if omitted)",
    )
    p_set.add_argument(
        "--value",
        help="Secret value (NOT recommended; use prompt instead)",
    )

    p_get = sub.add_parser("get", help="Read a secret")
    p_get.add_argument("service", help="Service name")
    p_get.add_argument("--username", help="Keyring username label (defaults from registry)")
    p_get.add_argument(
        "--pin",
        help="4-digit PIN for this entry (prompted if omitted)",
    )

    p_del = sub.add_parser("delete", help="Delete a secret")
    p_del.add_argument("service", help="Service name")
    p_del.add_argument("--username", help="Keyring username label (defaults from registry)")
    p_del.add_argument(
        "--pin",
        help="4-digit PIN for this entry (prompted if omitted)",
    )

    sub.add_parser("list", help="List known service/username entries (from local registry)")

    p_doc = sub.add_parser("doctor", help="Show diagnostics / config paths")
    p_doc.add_argument("--json", action="store_true", help="Output raw JSON")

    return p


def _prompt_pin(*, confirm: bool) -> str:
    while True:
        pin = getpass("4-digit PIN: ").strip()
        if not pin.isdigit() or len(pin) != 4:
            print("PIN must be exactly 4 digits.", file=sys.stderr)
            continue
        if confirm:
            pin2 = getpass("Confirm PIN: ").strip()
            if pin2 != pin:
                print("PINs did not match.", file=sys.stderr)
                continue
        return pin


def _cmd_set(args: argparse.Namespace) -> int:
    service: str = args.service
    username: str = args.username

    pin = args.pin if args.pin is not None else _prompt_pin(confirm=True)

    if args.value is not None:
        secret = args.value
    else:
        secret = getpass(f"Secret for {service}/{username}: ")

    if not secret:
        print("Refusing to store an empty secret.", file=sys.stderr)
        return 2

    try:
        set_secret(service=service, username=username, secret=secret, pin=pin)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    print(f"Saved secret for {service}/{username}.")
    return 0


def _cmd_get(args: argparse.Namespace) -> int:
    service: str = args.service

    try:
        username = resolve_username(service, args.username)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    pin = args.pin if args.pin is not None else _prompt_pin(confirm=False)

    try:
        secret = get_secret(service=service, username=username, pin=pin)
    except (KeyError, PermissionError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 1

    # Intentionally prints to stdout; caller can pipe to other programs.
    sys.stdout.write(secret)
    if not secret.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def _cmd_delete(args: argparse.Namespace) -> int:
    service: str = args.service

    try:
        username = resolve_username(service, args.username)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    pin = args.pin if args.pin is not None else _prompt_pin(confirm=False)

    try:
        delete_secret(service=service, username=username, pin=pin)
    except (PermissionError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        # keyring raises PasswordDeleteError; keep this generic but informative.
        print(f"Failed to delete {service}/{username}: {e}", file=sys.stderr)
        return 1

    print(f"Deleted secret for {service}/{username}.")
    return 0


def _cmd_list() -> int:
    items = list_services()
    if not items:
        print("No entries recorded yet. Use: apivault set <service>")
        return 0

    for item in items:
        print(f"{item.service}\t{item.username}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    info = doctor_info()
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"Config dir:    {info['config_dir']}")
        print(f"Registry path: {info['registry_path']}")
        kr = info["keyring"]
        print(f"Keyring:       {kr['type']}")
        print(f"Keyring repr:  {kr['repr']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = _build_parser()
    args = p.parse_args(argv)

    if args.cmd == "set":
        return _cmd_set(args)
    if args.cmd == "get":
        return _cmd_get(args)
    if args.cmd == "delete":
        return _cmd_delete(args)
    if args.cmd == "list":
        return _cmd_list()
    if args.cmd == "doctor":
        return _cmd_doctor(args)

    p.error("Unknown command")
    return 2
