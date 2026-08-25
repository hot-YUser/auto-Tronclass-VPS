#!/usr/bin/env python3
"""Manage revocable QR API keys with a local standard-library key store."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import time

from qr_common import ConfigError, env_text


WORKDIR = "/home/opc/qr-harvest"
KEYS_PATH = os.path.join(WORKDIR, "apikeys.json")
os.umask(0o077)


def configure(env=None):
    global WORKDIR, KEYS_PATH
    values = os.environ if env is None else env
    WORKDIR = env_text(
        values, "QR_WORKDIR", "/home/opc/qr-harvest", required=True)
    KEYS_PATH = os.path.join(WORKDIR, "apikeys.json")


def _now_iso(epoch=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _load():
    if not os.path.exists(KEYS_PATH):
        return []
    try:
        with open(KEYS_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError("cannot read API key store") from exc
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list) or not all(isinstance(item, dict) for item in keys):
        raise RuntimeError("invalid API key store")
    return keys


def _save(keys):
    tmp = KEYS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"keys": keys}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, KEYS_PATH)


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
        days = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a number")
    if not math.isfinite(days) or days <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return days


def cmd_create(args):
    key = secrets.token_urlsafe(24)
    kid = "k_" + secrets.token_hex(4)
    exp = int(time.time()) + int(args.ttl_days * 86400)
    record = {
        "id": kid,
        "hash": _hash(key),
        "label": args.label or "",
        "created_utc": _now_iso(),
        "expires_utc": _now_iso(exp),
        "expires_epoch": exp,
        "revoked": False,
    }
    keys = _load()
    keys.append(record)
    _save(keys)
    print("API key created（顯示一次，請立即保存）：")
    print("  id:      %s" % kid)
    print("  label:   %s" % (args.label or ""))
    print("  expires: %s (%s 天)" % (record["expires_utc"], args.ttl_days))
    print("  KEY:     %s" % key)


def cmd_list(args):
    del args
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
    keys = _load()
    found = False
    for record in keys:
        if record.get("id") == args.id:
            record["revoked"] = True
            found = True
    _save(keys)
    print("revoked %s" % args.id if found else "id not found: %s" % args.id)


def cmd_rm(args):
    keys = _load()
    count = len(keys)
    keys = [record for record in keys if record.get("id") != args.id]
    _save(keys)
    print("removed %s" % args.id if len(keys) < count else "id not found: %s" % args.id)


def cmd_purge(args):
    del args
    keys = _load()
    count = len(keys)
    keys = [record for record in keys if _status(record) == "active"]
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
    create.add_argument("--label", default="", help="備註（如裝置/用途）")
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
