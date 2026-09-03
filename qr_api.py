#!/usr/bin/env python3
"""Bounded read-only HTTP API for validated QR token records."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import queue
import re
import secrets
import signal
import socket
import threading
import time
import urllib.parse
from collections import OrderedDict
from dataclasses import dataclass
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Mapping, Optional

from qr_common import ConfigError, env_float, env_int, env_text
from qr_common import validate_api_key_store, validate_token_record, write_json_atomic


SOURCE_URL = "https://github.com/hot-YUser/auto-Tronclass-VPS"
SOURCE_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
SECURITY_HEADERS = (
    ("Cache-Control", "no-store, max-age=0"),
    ("Pragma", "no-cache"),
    ("Expires", "0"),
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Vary", "Authorization"),
)
ROUTE_ALLOW = {
    "/health": "GET, HEAD, OPTIONS",
    "/source": "GET, HEAD, OPTIONS",
    "/token": "GET, HEAD, OPTIONS",
    "/restart": "POST, OPTIONS",
}
_SAFE_METHOD = re.compile(r"[A-Z]{1,12}\Z")
_CONTROL_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_TERMINAL_CONTROL_STATUSES = {"completed", "rejected_preserve", "failed"}
MAX_JSON_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ApiConfig:
    api_key: str
    source_revision: str
    bind: str
    port: int
    stale_ms: int
    future_skew_ms: int
    workdir: str
    workers: int
    pending: int
    socket_timeout_seconds: float
    limiter_max_entries: int
    global_rate: float
    global_burst: int
    principal_rate: float
    principal_burst: int
    health_rate: float
    health_burst: int
    restart_rate: float
    restart_burst: int


def load_config(env: Optional[Mapping[str, str]] = None) -> ApiConfig:
    values = os.environ if env is None else env
    # Managed-key isolation: API process must not receive teacher credentials.
    for forbidden in ("QR_TEACHER_USER", "QR_TEACHER_PASS"):
        if str(values.get(forbidden, "")).strip():
            raise ConfigError("{} must not be set in API process".format(forbidden))
    bind = env_text(values, "QR_BIND", "127.0.0.1", required=True)
    try:
        bind_ip = ipaddress.ip_address(bind)
    except ValueError:
        if bind.lower() != "localhost":
            raise ConfigError("QR_BIND must be a loopback address")
    else:
        if not bind_ip.is_loopback:
            raise ConfigError("QR_BIND must be a loopback address")
    api_key = env_text(values, "QR_API_KEY", default="")
    if api_key and len(api_key) < 32:
        raise ConfigError("QR_API_KEY must contain at least 32 characters")
    source_revision = env_text(values, "QR_SOURCE_REVISION", required=True).lower()
    if SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        raise ConfigError("QR_SOURCE_REVISION must be a 40-character commit SHA")
    workdir = env_text(values, "QR_WORKDIR", "/home/opc/qr-harvest", required=True)
    if not (os.path.isabs(workdir) or workdir.startswith("/")):
        raise ConfigError("QR_WORKDIR must be absolute")
    return ApiConfig(
        api_key=api_key,
        source_revision=source_revision,
        bind=bind,
        port=env_int(values, "QR_PORT", 8741, minimum=1, maximum=65535),
        stale_ms=env_int(values, "QR_STALE_MS", 3000, minimum=1),
        future_skew_ms=env_int(values, "QR_FUTURE_SKEW_MS", 1000, minimum=0),
        workdir=workdir,
        # TasksMax=64 budget: at most 60 workers plus the main-thread task, keeping a small margin.
        workers=env_int(values, "QR_API_WORKERS", 4, minimum=1, maximum=60),
        pending=env_int(values, "QR_API_PENDING", 16, minimum=1, maximum=1024),
        socket_timeout_seconds=env_float(
            values, "QR_SOCKET_TIMEOUT_SECONDS", 10.0,
            minimum=0.0, minimum_exclusive=True, maximum=25.0),
        limiter_max_entries=env_int(
            values, "QR_LIMITER_MAX_ENTRIES", 1024, minimum=1, maximum=65536),
        global_rate=env_float(
            values, "QR_GLOBAL_RATE", 20.0, minimum=0.0, minimum_exclusive=True),
        global_burst=env_int(values, "QR_GLOBAL_BURST", 40, minimum=1),
        principal_rate=env_float(
            values, "QR_PRINCIPAL_RATE", 2.0, minimum=0.0, minimum_exclusive=True),
        principal_burst=env_int(values, "QR_PRINCIPAL_BURST", 4, minimum=1),
        health_rate=env_float(
            values, "QR_HEALTH_RATE", 5.0, minimum=0.0, minimum_exclusive=True),
        health_burst=env_int(values, "QR_HEALTH_BURST", 10, minimum=1),
        restart_rate=env_float(
            values, "QR_RESTART_RATE", 1.0 / 60.0,
            minimum=0.0, minimum_exclusive=True),
        restart_burst=env_int(values, "QR_RESTART_BURST", 1, minimum=1),
    )


def _read_json(path):
    try:
        if os.path.islink(path) or os.path.getsize(path) > MAX_JSON_BYTES:
            return None
        with open(path, "rb") as handle:
            raw = handle.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            return None
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, TypeError, ValueError):
        return None


@dataclass
class _BucketState:
    tokens: float
    updated: float


class TokenBucketTable:
    """Thread-safe monotonic token buckets with bounded LRU state."""

    def __init__(self, rate: float, burst: int, max_entries: int,
                 clock: Callable[[], float] = time.monotonic):
        if rate <= 0 or burst < 1 or max_entries < 1:
            raise ValueError("invalid token bucket bounds")
        self.rate = float(rate)
        self.burst = float(burst)
        self.max_entries = int(max_entries)
        self.clock = clock
        self._states = OrderedDict()
        self._lock = threading.Lock()

    @property
    def size(self):
        with self._lock:
            return len(self._states)

    def consume(self, key: str):
        now = float(self.clock())
        with self._lock:
            state = self._states.pop(key, None)
            if state is None:
                if len(self._states) >= self.max_entries:
                    self._states.popitem(last=False)
                state = _BucketState(self.burst, now)
            elapsed = max(0.0, now - state.updated)
            state.tokens = min(self.burst, state.tokens + elapsed * self.rate)
            state.updated = now
            if state.tokens >= 1.0:
                state.tokens -= 1.0
                allowed = True
                retry_after = 0.0
            else:
                allowed = False
                retry_after = (1.0 - state.tokens) / self.rate
            self._states[key] = state
            return allowed, retry_after


class RequestLimiter:
    def __init__(self, config: ApiConfig,
                 clock: Callable[[], float] = time.monotonic):
        self.global_table = TokenBucketTable(
            config.global_rate, config.global_burst, 1, clock)
        self.principal_table = TokenBucketTable(
            config.principal_rate, config.principal_burst,
            config.limiter_max_entries, clock)
        self.health_table = TokenBucketTable(
            config.health_rate, config.health_burst,
            config.limiter_max_entries, clock)
        self.restart_table = TokenBucketTable(
            config.restart_rate, config.restart_burst, 1, clock)

    def check(self, path: str, client_key: str):
        # Charge the route/client bucket first. Rejected traffic from one client must not drain
        # the global budget shared by healthy clients.
        checks = []
        if path == "/health":
            checks.append((self.health_table, client_key))
        else:
            checks.append((self.principal_table, client_key))
        checks.append((self.global_table, "global"))
        for table, key in checks:
            allowed, retry_after = table.consume(key)
            if not allowed:
                return False, retry_after
        return True, 0.0

    def check_restart(self):
        return self.restart_table.consume("restart")


class ApiApplication:
    def __init__(self, config: ApiConfig,
                 wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 log_sink=None):
        self.config = config
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self.log_sink = log_sink or self._print_log
        self.token_path = os.path.join(config.workdir, "token.json")
        self.state_path = os.path.join(config.workdir, "state.json")
        self.control_path = os.path.join(config.workdir, "control.json")
        self.control_ack_path = os.path.join(config.workdir, "control-ack.json")
        self.keys_path = os.path.join(config.workdir, "apikeys.json")
        self.limiter = RequestLimiter(config, monotonic)
        self._restart_lock = threading.Lock()

    @staticmethod
    def _print_log(entry):
        print(json.dumps(entry, ensure_ascii=True, separators=(",", ":"),
                         sort_keys=True), flush=True)

    def now_ms(self):
        return int(self.wall_clock() * 1000)

    @staticmethod
    def client_ip(peer: str, cloudflare_header: str = "") -> str:
        """Trust CF-Connecting-IP only from a loopback tunnel peer; return one canonical IP."""
        try:
            peer_ip = ipaddress.ip_address(str(peer or "").strip())
        except ValueError:
            return "unknown"
        header = str(cloudflare_header or "")
        if peer_ip.is_loopback and header and header.strip() == header:
            try:
                return ipaddress.ip_address(header).compressed
            except ValueError:
                pass
        return peer_ip.compressed

    @staticmethod
    def client_key(remote: str) -> str:
        return "ip:" + str(remote or "unknown")

    def is_master(self, token: str):
        return bool(self.config.api_key) and hmac.compare_digest(
            token.encode("utf-8"), self.config.api_key.encode("utf-8"))

    def is_managed(self, token: str):
        if not token:
            return False
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        data = _read_json(self.keys_path)
        try:
            keys = validate_api_key_store(data)
        except ValueError:
            return False
        now = int(self.wall_clock())
        for record in keys if isinstance(keys, list) else ():
            if not isinstance(record, dict):
                continue
            stored = record.get("hash")
            try:
                expires = int(record.get("expires_epoch", 0))
            except (TypeError, ValueError):
                continue
            if isinstance(stored, str) and stored \
                    and hmac.compare_digest(stored, digest) \
                    and record.get("revoked") is False and now < expires:
                return True
        return False

    def token_authorized(self, token: str):
        return self.is_master(token) or self.is_managed(token)

    def health(self):
        state = _read_json(self.state_path)
        token = _read_json(self.token_path)
        checked = validate_token_record(
            token, self.now_ms(), self.config.stale_ms,
            self.config.future_skew_ms)
        ok = isinstance(state, dict) and state.get("ok") is True and checked.valid
        payload = {
            "ok": ok,
            "status": "ok" if ok else "unhealthy",
            "token_fresh": checked.valid,
            "token_age_ms": checked.age_ms,
        }
        return (200 if ok else 503), payload

    def source_payload(self):
        return {
            "repository": SOURCE_URL,
            "license": "AGPL-3.0",
            "revision": self.config.source_revision,
        }

    def token_payload(self):
        token = _read_json(self.token_path)
        checked = validate_token_record(
            token, self.now_ms(), self.config.stale_ms,
            self.config.future_skew_ms)
        if not checked.valid:
            if checked.error == "stale":
                return 503, {"error": "stale", "age_ms": checked.age_ms}
            return 503, {"error": "no_data"}
        return 200, {
            "ok": True,
            "data": token["data"],
            "fetched_at_utc": token.get("fetched_at_utc"),
            "age_ms": checked.age_ms,
        }

    LEGACY_NONCE_RE = re.compile(r"[0-9]{10,15}\Z")
    def _restart_is_pending(self):
        request = _read_json(self.control_path)
        if not isinstance(request, dict) or request.get("cmd") != "restart":
            return False
        version = request.get("version")
        if isinstance(version, int) and not isinstance(version, bool) and version == 1:
            request_id = request.get("request_id")
            if not isinstance(request_id, str) \
                    or _CONTROL_REQUEST_ID_RE.fullmatch(request_id) is None:
                return False
            created = request.get("created_epoch_ms")
            if isinstance(created, bool) or not isinstance(created, int) or created <= 0:
                return False
            ack = _read_json(self.control_ack_path)
            if isinstance(ack, dict) and ack.get("status") in _TERMINAL_CONTROL_STATUSES \
                    and ack.get("request_id") == request_id:
                return False
            return True
        if version is None:
            nonce = request.get("nonce")
            if not isinstance(nonce, str) or self.LEGACY_NONCE_RE.fullmatch(nonce) is None:
                return False
            ack = _read_json(self.control_ack_path)
            return not (
                isinstance(ack, dict)
                and ack.get("request_id") == nonce
                and ack.get("status") in _TERMINAL_CONTROL_STATUSES
            )
        return False
    def request_restart(self):
        with self._restart_lock:
            state = _read_json(self.state_path)
            if isinstance(state, dict) and state.get("preserve") is True:
                return 409, {"error": "preserve_active"}
            if self._restart_is_pending():
                return 409, {"error": "restart_pending"}
            request_id = secrets.token_urlsafe(18)
            now = self.now_ms()
            request = {
                "version": 1,
                "cmd": "restart",
                "request_id": request_id,
                "created_epoch_ms": now,
                # Compat: include legacy nonce alias so an old keeper (nonce-only) can still restart.
                "nonce": str(now),
            }
            write_json_atomic(
                self.control_path,
                request,
                durable=True,
                separators=(",", ":"),
            )
        return 202, {
            "ok": True,
            "status": "accepted",
            "request_id": request_id,
            "restart_nonce": request_id,
        }

    def log_access(self, handler, status, duration_ms, response_bytes):
        method = getattr(handler, "command", "") or ""
        if _SAFE_METHOD.fullmatch(method) is None:
            method = "OTHER"
        raw_path = getattr(handler, "path", "") or ""
        try:
            parsed_path = urllib.parse.urlsplit(raw_path).path
        except ValueError:
            parsed_path = ""
        path = parsed_path if parsed_path in ROUTE_ALLOW else "other"
        remote = handler._client_ip()
        entry = {
            "event": "http_access",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.wall_clock())),
            "remote": remote,
            "method": method,
            "path": path,
            "status": int(status or 0),
            "duration_ms": max(0, int(duration_ms)),
            "response_bytes": max(0, int(response_bytes)),
        }
        self.log_sink(entry)

    def log_server_event(self, event, remote):
        self.log_sink({
            "event": event,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.wall_clock())),
            "remote": str(remote or ""),
        })


class Handler(BaseHTTPRequestHandler):
    server_version = "qr-api"
    sys_version = ""

    def version_string(self):
        return "qr-api"

    def log_message(self, fmt, *args):
        del fmt, args

    def log_request(self, code="-", size="-"):
        del code, size


    def handle(self):
        """Bounded handle: keep-alive loop must respect connection closure and errors."""
        self.close_connection = True
        try:
            self.handle_one_request()
            while not self.close_connection:
                self.handle_one_request()
        except Exception:
            self.close_connection = True
            try:
                self.server.app.log_server_event("request_error", self.client_address[0] if self.client_address else "")
            except Exception:
                pass

    def handle_one_request(self):
        self._access_started = self.server.app.monotonic()
        self._access_status = 0
        self._access_bytes = 0
        try:
            super().handle_one_request()
        finally:
            command = getattr(self, "command", "")
            if command or self._access_status:
                elapsed = (self.server.app.monotonic() - self._access_started) * 1000
                self.server.app.log_access(
                    self, self._access_status, elapsed, self._access_bytes)

    def send_response(self, code, message=None):
        self._access_status = int(code)
        super().send_response(code, message)

    def _path(self):
        try:
            return urllib.parse.urlsplit(self.path).path
        except ValueError:
            return ""

    def _bearer(self):
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return ""
        token = authorization[7:]
        if not token or token.strip() != token or any(char.isspace() for char in token):
            return ""
        return token

    def _send_headers(self, status, content_length, extra_headers=None,
                      content_type=None):
        self.close_connection = True
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Connection", "close")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Link", "<{}>; rel=\"source\"".format(SOURCE_URL))
        self.send_header("X-Source-Revision", self.server.app.config.source_revision)
        for name, value in extra_headers or ():
            self.send_header(name, value)
        self.end_headers()

    def _send(self, status, obj, extra_headers=None, head_only=False):
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_headers(
            status, len(body), extra_headers,
            content_type="application/json; charset=utf-8")
        if not head_only:
            try:
                self.wfile.write(body)
                self._access_bytes = len(body)
            except (BrokenPipeError, ConnectionResetError):
                self._access_bytes = 0

    def _send_empty(self, status, extra_headers=None):
        self._send_headers(status, 0, extra_headers)

    def send_error(self, code, message=None, explain=None):
        del message, explain
        # Parser-generated 4xx/5xx (400/414/431/505) must be rate-limited to protect bounded workers.
        # Avoid double-charging: only apply here for parser errors; route handlers already rate-limit.
        # Use direct limiter check without recursion (send_error -> _rate_allowed -> _send -> send_error).
        code_int = int(code)
        if code_int in (400, 414, 431, 505):
            client_key = self.server.app.client_key(self._client_ip())
            allowed, retry_after = self.server.app.limiter.check("other", client_key)
            if not allowed:
                # Parser already consumed; replace parser error with 429.
                self.close_connection = True
                try:
                    body = json.dumps({"error": "rate_limited"}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    self.send_response(429)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    for name, value in SECURITY_HEADERS:
                        self.send_header(name, value)
                    self.send_header("Link", "<{}>; rel=\"source\"".format(SOURCE_URL))
                    self.send_header("X-Source-Revision", self.server.app.config.source_revision)
                    self.send_header("Retry-After", str(max(1, int(math.ceil(retry_after)))))
                    self.end_headers()
                    if getattr(self, "command", "") != "HEAD":
                        try:
                            self.wfile.write(body)
                            self._access_bytes = len(body)
                        except (BrokenPipeError, ConnectionResetError):
                            self._access_bytes = 0
                except Exception:
                    pass
                return
            names = {
                400: "bad_request",
                414: "request_uri_too_long",
                431: "request_headers_too_large",
                505: "http_version_not_supported",
            }
            self._send(int(code), {"error": names.get(int(code), "request_error")},
                       head_only=(getattr(self, "command", "") == "HEAD"))
            return
        if int(code) == 501 and not self._rate_allowed(self._path()):
            return
        names = {
            400: "bad_request",
            404: "not_found",
            405: "method_not_allowed",
            414: "request_uri_too_long",
            431: "request_headers_too_large",
            501: "not_implemented",
            505: "http_version_not_supported",
        }
        self._send(int(code), {"error": names.get(int(code), "request_error")},
                   head_only=(getattr(self, "command", "") == "HEAD"))

    def _client_ip(self):
        peer = str(self.client_address[0]) if self.client_address else ""
        header = self.headers.get("CF-Connecting-IP", "") if hasattr(self, "headers") else ""
        return self.server.app.client_ip(peer, header)

    def _rate_allowed(self, path):
        client_key = self.server.app.client_key(self._client_ip())
        allowed, retry_after = self.server.app.limiter.check(path, client_key)
        if allowed:
            return True
        self._send(429, {"error": "rate_limited"},
                   (("Retry-After", str(max(1, int(math.ceil(retry_after))))),),
                   head_only=(getattr(self, "command", "") == "HEAD"))
        return False

    def _restart_rate_allowed(self):
        allowed, retry_after = self.server.app.limiter.check_restart()
        if allowed:
            return True
        self._send(
            429,
            {"error": "rate_limited"},
            (("Retry-After", str(max(1, int(math.ceil(retry_after))))),),
        )
        return False

    def _not_found_or_method(self, path, head_only=False):
        allow = ROUTE_ALLOW.get(path)
        if allow is None:
            self._send(404, {"error": "not_found"}, head_only=head_only)
        else:
            self._send(405, {"error": "method_not_allowed"},
                       (("Allow", allow),), head_only=head_only)

    def _dispatch_get(self, head_only=False):
        path = self._path()
        if not self._rate_allowed(path):
            return
        if path == "/health":
            status, payload = self.server.app.health()
            self._send(status, payload, head_only=head_only)
            return
        if path == "/source":
            self._send(200, self.server.app.source_payload(), head_only=head_only)
            return
        if path == "/token":
            token = self._bearer()
            if not self.server.app.token_authorized(token):
                self._send(401, {"error": "unauthorized"},
                           (("WWW-Authenticate", 'Bearer realm="qr-api"'),),
                           head_only=head_only)
                return
            status, payload = self.server.app.token_payload()
            self._send(status, payload, head_only=head_only)
            return
        self._not_found_or_method(path, head_only=head_only)

    def do_GET(self):
        self._dispatch_get()

    def do_HEAD(self):
        self._dispatch_get(head_only=True)

    def do_POST(self):
        path = self._path()
        if not self._rate_allowed(path):
            return
        if path == "/restart":
            if not self.server.app.is_master(self._bearer()):
                self._send(401, {"error": "unauthorized"},
                           (("WWW-Authenticate", 'Bearer realm="qr-api"'),))
                return
            if not self._restart_rate_allowed():
                return
            try:
                status, payload = self.server.app.request_restart()
            except OSError:
                self._send(503, {"error": "unavailable"})
                return
            self._send(status, payload)
            return
        self._not_found_or_method(path)

    def do_OPTIONS(self):
        path = self._path()
        if not self._rate_allowed(path):
            return
        allow = ROUTE_ALLOW.get(path)
        if allow is None:
            self._send(404, {"error": "not_found"})
            return
        self._send_empty(204, (("Allow", allow),))

    def _known_method_not_allowed(self):
        path = self._path()
        if not self._rate_allowed(path):
            return
        self._not_found_or_method(path,
                                  head_only=(getattr(self, "command", "") == "HEAD"))

    do_PUT = _known_method_not_allowed
    do_PATCH = _known_method_not_allowed
    do_DELETE = _known_method_not_allowed
    do_TRACE = _known_method_not_allowed
    do_CONNECT = _known_method_not_allowed


_SENTINEL = object()


class BoundedExecutor:
    """Fixed workers plus a queue with a strict pending-task bound."""

    def __init__(self, workers: int, max_pending: int, name="bounded",
                 error_handler=None):
        if workers < 1 or max_pending < 1:
            raise ValueError("workers and max_pending must be positive")
        self._queue = queue.Queue(maxsize=max_pending)
        self._closed = False
        self._lock = threading.Lock()
        self._error_handler = error_handler
        self._threads = [
            threading.Thread(target=self._worker,
                             name="{}-{}".format(name, index + 1), daemon=True)
            for index in range(workers)
        ]
        for thread in self._threads:
            thread.start()

    @property
    def worker_count(self):
        return len(self._threads)

    @property
    def pending_count(self):
        return self._queue.qsize()

    def submit(self, fn, *args):
        with self._lock:
            if self._closed:
                return False
            try:
                self._queue.put_nowait((fn, args))
            except queue.Full:
                return False
            return True

    def shutdown(self, wait=True, cancel_pending=None):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if cancel_pending is not None:
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    if item is not _SENTINEL:
                        _fn, args = item
                        try:
                            cancel_pending(*args)
                        except Exception as exc:
                            if self._error_handler is not None:
                                self._error_handler(exc)
                finally:
                    self._queue.task_done()
        for _ in self._threads:
            self._queue.put(_SENTINEL)
        if wait:
            for thread in self._threads:
                thread.join()

    def _worker(self):
        while True:
            item = self._queue.get()
            try:
                if item is _SENTINEL:
                    return
                fn, args = item
                try:
                    fn(*args)
                except Exception as exc:
                    if self._error_handler is not None:
                        self._error_handler(exc)
            finally:
                self._queue.task_done()


class BoundedHTTPServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, app: ApiApplication,
                 workers: int, pending: int, socket_timeout: float):
        self.app = app
        self.socket_timeout = socket_timeout
        self.request_queue_size = workers + pending
        self._executor = BoundedExecutor(
            workers, pending, name="qr-api", error_handler=self._executor_error)
        try:
            super().__init__(server_address, handler_class)
        except Exception:
            self._executor.shutdown()
            raise

    @property
    def executor(self):
        return self._executor

    def _executor_error(self, exc):
        del exc
        self.app.log_server_event("worker_error", "")

    def process_request(self, request, client_address):
        request.settimeout(self.socket_timeout)
        if not self._executor.submit(self._process_request, request, client_address):
            self._reject_busy(request, client_address)
            self.shutdown_request(request)

    def _process_request(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.app.log_server_event("request_error", client_address[0])
        finally:
            self.shutdown_request(request)

    def _reject_busy(self, request, client_address):
        body = b'{"error":"busy"}'
        lines = [
            "HTTP/1.0 503 Service Unavailable",
            "Server: qr-api",
            "Date: {}".format(formatdate(timeval=self.app.wall_clock(), usegmt=True)),
            "Content-Type: application/json; charset=utf-8",
            "Content-Length: {}".format(len(body)),
            "Connection: close",
        ]
        lines.extend("{}: {}".format(name, value) for name, value in SECURITY_HEADERS)
        lines.append("Link: <{}>; rel=\"source\"".format(SOURCE_URL))
        lines.append("X-Source-Revision: {}".format(self.app.config.source_revision))
        response = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body
        try:
            request.settimeout(min(self.socket_timeout, 0.05))
            request.sendall(response)
        except OSError:
            pass
        self.app.log_server_event("server_busy", client_address[0])

    def _cancel_pending_request(self, request, client_address):
        del client_address
        self.shutdown_request(request)

    def server_close(self):
        try:
            super().server_close()
        finally:
            self._executor.shutdown(cancel_pending=self._cancel_pending_request)


def make_server(config: ApiConfig, server_address=None,
                wall_clock: Callable[[], float] = time.time,
                monotonic: Callable[[], float] = time.monotonic,
                log_sink=None):
    address = server_address or (config.bind, config.port)
    app = ApiApplication(config, wall_clock, monotonic, log_sink)
    return BoundedHTTPServer(
        address, Handler, app, config.workers, config.pending,
        config.socket_timeout_seconds)


def main():
    config = load_config()
    os.umask(0o077)
    server = make_server(config)
    stop_event = threading.Event()

    def stop(signum, frame):
        del signum, frame
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.timeout = 0.5
    try:
        while not stop_event.is_set():
            server.handle_request()
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
