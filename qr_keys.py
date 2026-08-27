#!/usr/bin/env python3
"""Manage revocable QR API keys with a local standard-library key store."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import secrets
import threading
import time

from qr_common import ConfigError, MAX_KEY_LABEL_LENGTH, env_float, env_text
from qr_common import validate_api_key_store, write_json_atomic


WORKDIR = "/home/opc/qr-harvest"
KEYS_PATH = os.path.join(WORKDIR, "apikeys.json")
MAX_STORE_BYTES = 1024 * 1024
MAX_LABEL_LENGTH = MAX_KEY_LABEL_LENGTH
_LOCAL_STORE_LOCK = threading.Lock()
try:
    import fcntl
except ImportError:  # pragma: no cover - production is Linux; local Windows tests use process lock
    fcntl = None
os.umask(0o077)


def configure(env=None):
    global WORKDIR, KEYS_PATH
    values = os.environ if env is None else env
    WORKDIR = env_text(
        values, "QR_WORKDIR", "/home/opc/qr-harvest", required=True)
    KEYS_PATH = os.path.join(WORKDIR, "apikeys.json")


def _now_iso(epoch=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


@contextmanager
def _store_lock(exclusive=True):
    os.makedirs(WORKDIR, mode=0o700, exist_ok=True)
    lock_path = KEYS_PATH + ".lock"
    with _LOCAL_STORE_LOCK:
        with open(lock_path, "a+b") as lock:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _validate_keys(keys):
    try:
        return validate_api_key_store({"keys": keys})
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc


def _load():
    if not os.path.exists(KEYS_PATH):
        return []
    try:
        if os.path.islink(KEYS_PATH) or os.path.getsize(KEYS_PATH) > MAX_STORE_BYTES:
            raise RuntimeError("invalid API key store")
        with open(KEYS_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except RuntimeError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError("cannot read API key store") from exc
    keys = data.get("keys") if isinstance(data, dict) else None
    return _validate_keys(keys)


def _save(keys):
    validated = _validate_keys(keys)
    write_json_atomic(
        KEYS_PATH,
        {"keys": validated},
        durable=True,
        ensure_ascii=False,
        indent=1,
    )


def _hash(key):
    return hashlib.sha256(key.encode()).hexdigest()


def _status(record):
    if record.get("revoked"):
        return "revoked"
    try:
        expires = int(record.get("expires_epoch", 0))
    except (TypeError, ValueError):
        return "invalid"
    if int(time.time()) >= expires:
        return "expired"
    return "active"


def positive_days(value):
    try:
        days = env_float(
            {"TTL_DAYS": str(value)}, "TTL_DAYS", 1.0,
            minimum=1.0 / 86400.0, maximum=3650.0)
    except ConfigError as exc:
        raise argparse.ArgumentTypeError(
            "must be between one second and 3650 days") from exc
    return days


def safe_label(value):
    label = str(value or "")
    if len(label) > MAX_LABEL_LENGTH or any(
            ord(char) < 32 or ord(char) == 127 for char in label):
        raise argparse.ArgumentTypeError(
            "label must be at most {} printable characters".format(MAX_LABEL_LENGTH))
    return label


def cmd_create(args):
    key = secrets.token_urlsafe(24)
    exp = int(time.time()) + int(args.ttl_days * 86400)
    with _store_lock(exclusive=True):
        keys = _load()
        existing_ids = {record["id"] for record in keys}
        kid = ""
        for _ in range(32):
            candidate = "k_" + secrets.token_hex(4)
            if candidate not in existing_ids:
                kid = candidate
                break
        if not kid:
            raise RuntimeError("cannot allocate API key id")
        record = {
            "id": kid,
            "hash": _hash(key),
            "label": args.label or "",
            "created_utc": _now_iso(),
            "expires_utc": _now_iso(exp),
            "expires_epoch": exp,
            "revoked": False,
        }
        keys.append(record)
        _save(keys)
    print("API key created（顯示一次，請立即保存）：")
    print("  id:      %s" % kid)
    print("  label:   %s" % (args.label or ""))
    print("  expires: %s (%s 天)" % (record["expires_utc"], args.ttl_days))
    print("  KEY:     %s" % key)


def cmd_list(args):
    del args
    with _store_lock(exclusive=False):
        keys = _load()
    if not keys:
        print("(no keys)")
        return
    print("%-14s %-9s %-21s %s" % ("id", "status", "expires_utc", "label"))
    for record in keys:
        print("%-14s %-9s %-21s %s" % (
            record.get("id"), _status(record), record.get("expires_utc"),
            record.get("label", "")))


def cmd_revoke(args):
    with _store_lock(exclusive=True):
        keys = _load()
        found = False
        for record in keys:
            if record.get("id") == args.id:
                record["revoked"] = True
                found = True
        if found:
            _save(keys)
    print("revoked %s" % args.id if found else "id not found: %s" % args.id)


def cmd_rm(args):
    with _store_lock(exclusive=True):
        keys = _load()
        count = len(keys)
        keys = [record for record in keys if record.get("id") != args.id]
        if len(keys) < count:
            _save(keys)
    print("removed %s" % args.id if len(keys) < count else "id not found: %s" % args.id)


def cmd_purge(args):
    del args
    with _store_lock(exclusive=True):
        keys = _load()
        count = len(keys)
        keys = [record for record in keys if _status(record) == "active"]
        if len(keys) < count:
            _save(keys)
    print("purged %d expired/revoked" % (count - len(keys)))


def main():
    try:
        configure()
    except ConfigError as exc:
        raise SystemExit("configuration error: {}".format(exc))
    os.makedirs(WORKDIR, mode=0o700, exist_ok=True)
    parser = argparse.ArgumentParser(description="QR data API key management")
    sub = parser.add_subparsers(dest="cmd")
    create = sub.add_parser("create", help="建立一把隨機 key")
    create.add_argument("--ttl-days", type=positive_days, required=True, help="有效天數")
    create.add_argument("--label", type=safe_label, default="", help="備註（如裝置/用途）")
    sub.add_parser("list", help="列出所有 key 與狀態")
    revoke = sub.add_parser("revoke", help="即時撤銷一把 key")
    revoke.add_argument("id")
    remove = sub.add_parser("rm", help="刪除一把 key 紀錄")
    remove.add_argument("id")
    sub.add_parser("purge", help="清掉已過期/已撤銷")
    args = parser.parse_args()
    handlers = {
        "create": cmd_create,
        "list": cmd_list,
        "revoke": cmd_revoke,
        "rm": cmd_rm,
        "purge": cmd_purge,
    }
    function = handlers.get(args.cmd)
    if function is None:
        parser.print_help()
        return
    function(args)


if __name__ == "__main__":
    main()
