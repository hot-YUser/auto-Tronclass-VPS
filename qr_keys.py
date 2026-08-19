#!/usr/bin/env python3
"""QR data API 金鑰管理 CLI（純 stdlib）。

建立/列出/撤銷/清除隨機 API Key，每把 Key 有獨立 TTL（天）。金鑰以 sha256 雜湊儲存於
WORKDIR/apikeys.json（明文只在建立當下印一次，之後無法還原）；qr_api 每次請求重讀此檔，
故新建/撤銷即時生效、免重啟任何服務。

用法（在 VPS 上）：
  python3 qr_keys.py create --ttl-days 10 [--label phone]
  python3 qr_keys.py list
  python3 qr_keys.py revoke <id>
  python3 qr_keys.py rm <id>
  python3 qr_keys.py purge            # 刪掉已過期/已撤銷
環境變數 QR_WORKDIR 指定 apikeys.json 所在（預設 /home/opc/qr-harvest）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import time

WORKDIR = os.environ.get("QR_WORKDIR", "/home/opc/qr-harvest")
KEYS_PATH = os.path.join(WORKDIR, "apikeys.json")
os.umask(0o077)


def _now_iso(epoch=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _load():
    try:
        with open(KEYS_PATH, encoding="utf-8") as f:
            d = json.load(f)
        return d.get("keys", []) if isinstance(d, dict) else []
    except Exception:
        return []


def _save(keys):
    tmp = KEYS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"keys": keys}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, KEYS_PATH)


def _hash(k):
    return hashlib.sha256(k.encode()).hexdigest()


def _status(k):
    if k.get("revoked"):
        return "revoked"
    if int(time.time()) >= int(k.get("expires_epoch", 0)):
        return "expired"
    return "active"


def cmd_create(args):
    key = secrets.token_urlsafe(24)
    kid = "k_" + secrets.token_hex(4)
    exp = int(time.time()) + int(float(args.ttl_days) * 86400)
    rec = {"id": kid, "hash": _hash(key), "label": args.label or "",
           "created_utc": _now_iso(), "expires_utc": _now_iso(exp),
           "expires_epoch": exp, "revoked": False}
    keys = _load()
    keys.append(rec)
    _save(keys)
    print("API key created（顯示一次，請立即保存）：")
    print("  id:      %s" % kid)
    print("  label:   %s" % (args.label or ""))
    print("  expires: %s (%s 天)" % (rec["expires_utc"], args.ttl_days))
    print("  KEY:     %s" % key)


def cmd_list(args):
    keys = _load()
    if not keys:
        print("(no keys)")
        return
    print("%-14s %-9s %-21s %s" % ("id", "status", "expires_utc", "label"))
    for k in keys:
        print("%-14s %-9s %-21s %s" % (k.get("id"), _status(k), k.get("expires_utc"), k.get("label", "")))


def cmd_revoke(args):
    keys = _load()
    found = False
    for k in keys:
        if k.get("id") == args.id:
            k["revoked"] = True
            found = True
    _save(keys)
    print("revoked %s" % args.id if found else "id not found: %s" % args.id)


def cmd_rm(args):
    keys = _load()
    n = len(keys)
    keys = [k for k in keys if k.get("id") != args.id]
    _save(keys)
    print("removed %s" % args.id if len(keys) < n else "id not found: %s" % args.id)


def cmd_purge(args):
    keys = _load()
    n = len(keys)
    keys = [k for k in keys if _status(k) == "active"]
    _save(keys)
    print("purged %d expired/revoked" % (n - len(keys)))


def main():
    ap = argparse.ArgumentParser(description="QR data API key management (與核心分離)")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("create", help="建立一把隨機 key")
    c.add_argument("--ttl-days", type=float, required=True, help="有效天數")
    c.add_argument("--label", default="", help="備註（如裝置/用途）")
    sub.add_parser("list", help="列出所有 key 與狀態")
    r = sub.add_parser("revoke", help="即時撤銷一把 key")
    r.add_argument("id")
    d = sub.add_parser("rm", help="刪除一把 key 紀錄")
    d.add_argument("id")
    sub.add_parser("purge", help="清掉已過期/已撤銷")
    args = ap.parse_args()
    handlers = {"create": cmd_create, "list": cmd_list, "revoke": cmd_revoke,
                "rm": cmd_rm, "purge": cmd_purge}
    fn = handlers.get(args.cmd)
    if fn is None:
        ap.print_help()
        return
    fn(args)


if __name__ == "__main__":
    main()
