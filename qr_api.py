#!/usr/bin/env python3
"""TronClass QR data 唯讀 API（純 stdlib，Python 3.7+）。

與 keeper 解耦：只讀 keeper 寫在 WORKDIR 的 token.json / state.json，本進程不持有任何
session/cookie，可自由重啟、升級而不中斷 keeper。/token 需帶有效受管 API Key（由 qr_keys.py
建立、存 apikeys.json、每把獨立 TTL、可即時撤銷）；本進程每次請求重讀 apikeys.json，故新建/
撤銷即時生效、免重啟。master key（QR_API_KEY，選用）為 admin，可用於 /token 與 /restart。

端點：
- GET  /health   健康面（無驗證；state.json + 即時 token_age_ms，不含 token 本體）
- GET  /token    最新 data token（Authorization: Bearer <有效 API Key>；過期回 503）
- POST /restart  請 keeper 重建點名（Bearer <master key>；寫 control.json）

預設綁 127.0.0.1。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = os.environ.get("QR_API_KEY", "")  # master/admin key（選用）
BIND = os.environ.get("QR_BIND", "127.0.0.1")
PORT = int(os.environ.get("QR_PORT", "8741"))
STALE_MS = int(os.environ.get("QR_STALE_MS", "3000"))
WORKDIR = os.environ.get("QR_WORKDIR", "/home/opc/qr-harvest")

TOKEN_PATH = os.path.join(WORKDIR, "token.json")
STATE_PATH = os.path.join(WORKDIR, "state.json")
CONTROL_PATH = os.path.join(WORKDIR, "control.json")
KEYS_PATH = os.path.join(WORKDIR, "apikeys.json")


def _utc_ms():
    return int(time.time() * 1000)


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _token_age_ms(tok):
    if isinstance(tok, dict) and tok.get("ts"):
        try:
            return _utc_ms() - int(tok["ts"]) * 1000
        except Exception:
            return None
    return None


def _bearer(handler):
    auth = handler.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else ""


def _is_master(token):
    return bool(API_KEY) and hmac.compare_digest(token.encode(), API_KEY.encode())


def _is_valid_managed_key(token):
    """每次請求重讀 apikeys.json：撤銷/新建即時生效。有效＝雜湊命中且未撤銷且未過期。"""
    if not token:
        return False
    h = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    d = _read_json(KEYS_PATH)
    keys = d.get("keys", []) if isinstance(d, dict) else []
    for k in keys:
        kh = k.get("hash", "")
        if kh and hmac.compare_digest(kh, h) and not k.get("revoked") \
                and now < int(k.get("expires_epoch", 0)):
            return True
    return False


def _authorized_token(handler):
    tok = _bearer(handler)
    return _is_master(tok) or _is_valid_managed_key(tok)


def _authorized_admin(handler):
    return _is_master(_bearer(handler))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            st = _read_json(STATE_PATH) or {"ok": False, "error": "no state.json"}
            st["token_age_ms"] = _token_age_ms(_read_json(TOKEN_PATH))
            self._send(200, st)
        elif self.path == "/token":
            if not _authorized_token(self):
                self._send(401, {"error": "unauthorized"})
                return
            tok = _read_json(TOKEN_PATH)
            if not tok or not tok.get("ok") or not tok.get("data"):
                self._send(503, {"error": "no_data"})
                return
            age = _token_age_ms(tok)
            if age is None or age > STALE_MS:
                self._send(503, {"error": "stale", "age_ms": age})
                return
            self._send(200, {"ok": True, "data": tok["data"],
                             "fetched_at_utc": tok.get("fetched_at_utc"), "age_ms": age})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/restart":
            if not _authorized_admin(self):
                self._send(401, {"error": "unauthorized"})
                return
            nonce = str(int(time.time() * 1000))
            tmp = CONTROL_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"cmd": "restart", "nonce": nonce}, f)
            os.replace(tmp, CONTROL_PATH)
            self._send(200, {"ok": True, "restart_nonce": nonce})
        else:
            self._send(404, {"error": "not found"})


def main():
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
