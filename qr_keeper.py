#!/usr/bin/env python3
"""TronClass QR token harvester (Python 3.9+, standard library only).

The keeper maintains a teacher session and an in-progress QR rollcall, writes a
strictly validated token record atomically, and publishes a small local state
record for the separate read-only API. Its self-check is passive: it only reads
and validates the local token record.
"""
from __future__ import annotations

import calendar
import gzip
import html
import http.cookiejar
import json
import os
import re
import shutil
import signal
import socket
import threading
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Optional

from qr_common import ConfigError, env_bool, env_choice, env_float, env_int, env_text
from qr_common import env_utc_date, validate_token_record
from qr_common import write_json_atomic as _write_json_atomic


@dataclass(frozen=True)
class KeeperConfig:
    base: str
    course_id: str
    teacher_user: str
    teacher_pass: str
    source_revision: str
    poll_seconds: float
    workdir: str
    passive_check_seconds: float
    state_write_seconds: float
    cookie_resave_seconds: float
    rollcall_duration: str
    preserve_mode: str
    preserve_after: str
    stale_ms: int
    future_skew_ms: int
    socket_timeout_seconds: float
    corpus_enabled: bool
    corpus_max_bytes: int
    corpus_max_days: int
    corpus_min_free_bytes: int
    corpus_flush_records: int


class AuthenticationLost(RuntimeError):
    """The teacher session is no longer authenticated."""


def load_config(env: Optional[Mapping[str, str]] = None) -> KeeperConfig:
    values = os.environ if env is None else env
    base = env_text(values, "QR_BASE", "https://www.tronclass.com.tw", required=True).rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in ("http", "https") or not parsed.hostname \
            or parsed.username is not None or parsed.password is not None \
            or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ConfigError("QR_BASE must be an http(s) origin without credentials")
    workdir = env_text(values, "QR_WORKDIR", "/home/opc/qr-harvest", required=True)
    if not (os.path.isabs(workdir) or workdir.startswith("/")):
        raise ConfigError("QR_WORKDIR must be absolute")
    course_id = str(env_int(values, "QR_COURSE_ID", 0, minimum=1))
    preserve_mode = env_choice(
        values, "QR_PRESERVE_MODE", "auto", ("on", "off", "auto"))
    preserve_after = env_utc_date(
        values, "QR_PRESERVE_AFTER", required=(preserve_mode == "auto"))
    duration = env_text(values, "QR_ROLLCALL_DURATION_SECONDS", default="")
    if duration and (not duration.isdigit() or int(duration) <= 0):
        raise ConfigError("QR_ROLLCALL_DURATION_SECONDS must be a positive integer")
    source_revision = env_text(values, "QR_SOURCE_REVISION", required=True).lower()
    if SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        raise ConfigError("QR_SOURCE_REVISION must be a 40-character commit SHA")
    return KeeperConfig(
        base=base,
        course_id=course_id,
        teacher_user=env_text(values, "QR_TEACHER_USER", required=True),
        teacher_pass=env_text(values, "QR_TEACHER_PASS", required=True),
        source_revision=source_revision,
        poll_seconds=env_float(values, "QR_POLL_SECONDS", 0.5,
                               minimum=0.0, minimum_exclusive=True),
        workdir=workdir,
        passive_check_seconds=env_float(
            values, "QR_PASSIVE_CHECK_SECONDS", 5.0,
            minimum=0.0, minimum_exclusive=True),
        state_write_seconds=env_float(
            values, "QR_STATE_WRITE_SECONDS", 5.0,
            minimum=0.0, minimum_exclusive=True),
        cookie_resave_seconds=env_float(
            values, "QR_COOKIE_RESAVE_SECONDS", 300.0,
            minimum=0.0, minimum_exclusive=True),
        rollcall_duration=duration,
        preserve_mode=preserve_mode,
        preserve_after=preserve_after,
        stale_ms=env_int(values, "QR_STALE_MS", 3000, minimum=1),
        future_skew_ms=env_int(values, "QR_FUTURE_SKEW_MS", 1000, minimum=0),
        socket_timeout_seconds=env_float(
            values, "QR_SOCKET_TIMEOUT_SECONDS", 20.0,
            minimum=0.0, minimum_exclusive=True, maximum=25.0),
        corpus_enabled=env_bool(values, "QR_CORPUS_ENABLED", False),
        corpus_max_bytes=env_int(
            values, "QR_CORPUS_MAX_BYTES", 15 * 1024 ** 3,
            minimum=1024 * 1024),
        corpus_max_days=env_int(
            values, "QR_CORPUS_MAX_DAYS", 30, minimum=1, maximum=3650),
        corpus_min_free_bytes=env_int(
            values, "QR_CORPUS_MIN_FREE_BYTES", 5 * 1024 ** 3,
            minimum=0),
        corpus_flush_records=env_int(
            values, "QR_CORPUS_FLUSH_RECORDS", 20,
            minimum=1, maximum=10000),
    )


BASE = "https://www.tronclass.com.tw"
COURSE_ID = ""
TEACHER_USER = ""
TEACHER_PASS = ""
SOURCE_REVISION = ""
POLL_SECONDS = 0.5
WORKDIR = "/home/opc/qr-harvest"
PASSIVE_CHECK_SECONDS = 5.0
STATE_WRITE_SECONDS = 5.0
COOKIE_RESAVE_SECONDS = 300.0
_ROLLCALL_DURATION_ENV = ""
PRESERVE_MODE = "off"
PRESERVE_AFTER = ""
STALE_MS = 3000
FUTURE_SKEW_MS = 1000
SOCKET_TIMEOUT_SECONDS = 20.0
CORPUS_ENABLED = False
CORPUS_MAX_BYTES = 15 * 1024 ** 3
CORPUS_MAX_DAYS = 30
CORPUS_MIN_FREE_BYTES = 5 * 1024 ** 3
CORPUS_FLUSH_RECORDS = 20
MAX_HTTP_BODY_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024

COOKIE_PATH = os.path.join(WORKDIR, "cookies.txt")
TOKEN_PATH = os.path.join(WORKDIR, "token.json")
STATE_PATH = os.path.join(WORKDIR, "state.json")
CONTROL_PATH = os.path.join(WORKDIR, "control.json")
CONTROL_ACK_PATH = os.path.join(WORKDIR, "control-ack.json")
RID_PATH = os.path.join(WORKDIR, "rollcall.json")

CONTROL_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
LEGACY_NONCE_RE = re.compile(r"[0-9]{10,15}\Z")
FORM_JSON_RE = re.compile(r":email-login-form\s*=\s*(['\"])(.*?)\1", re.S)
SOURCE_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
HIDDEN_RE = re.compile(r"email-login-hidden-tag\s*=\s*(['\"])(.*?)\1", re.S)

os.umask(0o077)
STOP_EVENT = threading.Event()
LOCK = threading.Lock()
STATE = {
    "ok": False,
    "preserve": False,
    "rollcall_id": "",
    "rollcall_duration": 0,
    "rollcall_finished_at": "",
    "rollcall_status": "",
    "last_fetch_utc": "",
    "age_ms": -1,
    "session_since_utc": "",
    "logins": 0,
    "recreated": 0,
    "last_error": "",
    "preserve_alert": "",
    "passive_check_last": {},
    "corpus_bytes": 0,
    "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}


def apply_config(config: KeeperConfig) -> None:
    global BASE, COURSE_ID, TEACHER_USER, TEACHER_PASS, SOURCE_REVISION, POLL_SECONDS, WORKDIR
    global PASSIVE_CHECK_SECONDS, STATE_WRITE_SECONDS, COOKIE_RESAVE_SECONDS
    global _ROLLCALL_DURATION_ENV, PRESERVE_MODE, PRESERVE_AFTER
    global STALE_MS, FUTURE_SKEW_MS, SOCKET_TIMEOUT_SECONDS
    global CORPUS_ENABLED, CORPUS_MAX_BYTES, CORPUS_MAX_DAYS
    global CORPUS_MIN_FREE_BYTES, CORPUS_FLUSH_RECORDS
    global COOKIE_PATH, TOKEN_PATH, STATE_PATH, CONTROL_PATH, CONTROL_ACK_PATH, RID_PATH
    BASE = config.base
    COURSE_ID = config.course_id
    TEACHER_USER = config.teacher_user
    TEACHER_PASS = config.teacher_pass
    SOURCE_REVISION = config.source_revision
    POLL_SECONDS = config.poll_seconds
    WORKDIR = config.workdir
    PASSIVE_CHECK_SECONDS = config.passive_check_seconds
    STATE_WRITE_SECONDS = config.state_write_seconds
    COOKIE_RESAVE_SECONDS = config.cookie_resave_seconds
    _ROLLCALL_DURATION_ENV = config.rollcall_duration
    PRESERVE_MODE = config.preserve_mode
    PRESERVE_AFTER = config.preserve_after
    STALE_MS = config.stale_ms
    FUTURE_SKEW_MS = config.future_skew_ms
    SOCKET_TIMEOUT_SECONDS = config.socket_timeout_seconds
    CORPUS_ENABLED = config.corpus_enabled
    CORPUS_MAX_BYTES = config.corpus_max_bytes
    CORPUS_MAX_DAYS = config.corpus_max_days
    CORPUS_MIN_FREE_BYTES = config.corpus_min_free_bytes
    CORPUS_FLUSH_RECORDS = config.corpus_flush_records
    COOKIE_PATH = os.path.join(WORKDIR, "cookies.txt")
    TOKEN_PATH = os.path.join(WORKDIR, "token.json")
    STATE_PATH = os.path.join(WORKDIR, "state.json")
    CONTROL_PATH = os.path.join(WORKDIR, "control.json")
    CONTROL_ACK_PATH = os.path.join(WORKDIR, "control-ack.json")
    RID_PATH = os.path.join(WORKDIR, "rollcall.json")


def _now_utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _utc_ms():
    return int(time.time() * 1000)


def _get():
    with LOCK:
        return dict(STATE)


def _set(**kw):
    with LOCK:
        STATE.update(kw)


def _http_error_summary(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return "HTTP {}".format(exc.code)
    if isinstance(exc, RuntimeError):
        return str(exc)[:160]
    return type(exc).__name__


def _read_json(path):
    try:
        if os.path.islink(path) or os.path.getsize(path) > MAX_JSON_BYTES:
            return None
        with open(path, "rb") as handle:
            raw = handle.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            return None
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return None


def preserve_active(current_date=None):
    """Return whether the configured cookie-preservation mode is active."""
    if PRESERVE_MODE == "on":
        return True
    if PRESERVE_MODE == "off":
        return False
    today = current_date or time.strftime("%Y-%m-%d", time.gmtime())
    return bool(PRESERVE_AFTER) and today >= PRESERVE_AFTER


def _load_jar(path):
    jar = http.cookiejar.LWPCookieJar(path)
    if os.path.exists(path):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except (OSError, http.cookiejar.LoadError):
            pass
    return jar


def _save_jar_atomic(jar, path):
    parent = os.path.dirname(os.path.abspath(path)) or "."
    descriptor, tmp = tempfile.mkstemp(
        prefix=".{}-".format(os.path.basename(path)),
        suffix=".tmp",
        dir=parent,
    )
    os.close(descriptor)
    try:
        os.chmod(tmp, 0o600)
        jar.save(filename=tmp, ignore_discard=True, ignore_expires=True)
        with open(tmp, "rb") as handle:
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            directory = -1
        if directory >= 0:
            try:
                os.fsync(directory)
            except OSError:
                pass
            finally:
                os.close(directory)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _opener(jar):
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _read_http_text(response, limit=MAX_HTTP_BODY_BYTES):
    raw = response.read(int(limit) + 1)
    if len(raw) > int(limit):
        raise RuntimeError("upstream response too large")
    return raw.decode("utf-8", "replace")


def _json_req(op, url, payload=None, method=None):
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with op.open(req) as resp:
            raw = _read_http_text(resp)
            status = getattr(resp, "status", 200)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            exc.close()
            raise AuthenticationLost("teacher session unauthorized")
        status = exc.code
        try:
            raw = _read_http_text(exc)
        finally:
            exc.close()
    try:
        return status, json.loads(raw)
    except (TypeError, ValueError):
        return status, None


def session_valid(op):
    try:
        status, body = _json_req(op, BASE + "/api/my-courses")
    except AuthenticationLost:
        return False
    if status != 200 or not isinstance(body, dict):
        return False
    courses = body.get("courses")
    return isinstance(courses, list)


def login(user, passwd, jar):
    """Open a teacher email session and keep cookies in the supplied jar."""
    op = _opener(jar)
    with op.open(BASE + "/login") as response:
        page = _read_http_text(response)
    mj = FORM_JSON_RE.search(page)
    mh = HIDDEN_RE.search(page)
    fields = {}
    if mj:
        try:
            value = json.loads(html.unescape(mj.group(2)))
            if isinstance(value, dict):
                fields.update(value)
        except (TypeError, ValueError):
            pass
    if mh:
        for tag in re.findall(r"<input\b[^>]*>", html.unescape(mh.group(2)), re.I):
            attrs = dict(re.findall(r'([\w-]+)\s*=\s*"([^"]*)"', tag))
            if attrs.get("name"):
                fields[attrs["name"]] = attrs.get("value", "")
    nxt = str(fields.get("next") or "").strip()
    fields["email"] = user
    fields["password"] = passwd
    fields["submit"] = "login"
    fields.setdefault("remember_me", "true")
    url = BASE + "/login?login=email"
    if nxt:
        url += "&next=" + urllib.parse.quote(nxt)
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode())
    with op.open(req) as response:
        _read_http_text(response)
    if not session_valid(op):
        raise AuthenticationLost("login validation failed")
    return op


def build_qr_payload(title):
    """Build the teacher-side QR rollcall creation payload."""
    return {
        "title": title,
        "status": "in_progress",
        "is_radar": False,
        "is_number": False,
        "type": "qr_rollcall",
        "number_code": "",
        "altitude": None,
        "latitude": None,
        "longitude": None,
        "use_beacon": False,
        "duration": 0,
        "student_rollcalls": [],
    }


def extract_rollcall_id(body):
    if isinstance(body, dict):
        for key in ("id", "rollcall_id", "rollcallId"):
            value = body.get(key)
            if value not in (None, ""):
                return str(value)
        for key in ("rollcall", "data"):
            nested = extract_rollcall_id(body.get(key))
            if nested:
                return nested
    return ""


def _max_rollcall_duration():
    try:
        return max(0, int(calendar.timegm(
            (9999, 1, 1, 0, 0, 0, 0, 0, 0)) - time.time()))
    except (OverflowError, OSError, ValueError):
        return 157680000000


def _duration_ladder():
    top = int(_ROLLCALL_DURATION_ENV) if _ROLLCALL_DURATION_ENV else _max_rollcall_duration()
    return (top, 3153600000, 31536000, 2592000, 86400, 7200, 0)


def create_rollcall(op):
    last_status = 0
    seen = set()
    for duration in _duration_ladder():
        duration = max(0, int(duration))
        if duration in seen:
            continue
        seen.add(duration)
        payload = build_qr_payload(time.strftime("%Y.%m.%d %H:%M", time.gmtime()))
        payload["duration"] = duration
        status, body = _json_req(
            op, BASE + "/api/course/{}/rollcall".format(COURSE_ID), payload)
        rid = extract_rollcall_id(body)
        if not rid:
            last_status = status
            continue
        start_status, _start_body = _json_req(
            op,
            BASE + "/api/rollcall/{}/start-rollcall".format(rid),
            {"duration": duration} if duration > 0 else None,
            "POST",
        )
        if start_status not in (200, 201, 204):
            last_status = start_status
            try:
                stop_rollcall(op, rid)
            except (OSError, urllib.error.URLError, AuthenticationLost):
                pass
            continue
        _set(rollcall_duration=duration)
        return rid
    raise RuntimeError("create rollcall failed (HTTP {})".format(last_status))


def _record_rollcall_meta(op, rid):
    try:
        for row in list_rollcalls(op):
            if extract_rollcall_id(row) == str(rid):
                _set(rollcall_finished_at=str(row.get("end_time") or ""),
                     rollcall_status=str(row.get("status") or ""))
                return True
    except (OSError, TypeError, ValueError, urllib.error.URLError):
        pass
    return False


def list_rollcalls(op):
    status, body = _json_req(op, BASE + "/api/course/{}/rollcalls".format(COURSE_ID))
    if status != 200 or not isinstance(body, dict):
        return []
    rows = body.get("rollcalls")
    return rows if isinstance(rows, list) else []


def live_qr_rollcall(op):
    for row in list_rollcalls(op):
        if str(row.get("status", "")) == "in_progress" and \
                str(row.get("type", "")) in ("qr_rollcall", "qr"):
            return extract_rollcall_id(row)
    return ""


def stop_rollcall(op, rid):
    status, _body = _json_req(
        op,
        BASE + "/api/rollcall/{}/stop_qr_rollcall".format(rid),
        payload=None,
        method="PUT",
    )
    return status in (200, 201, 204)


def _rollcall_in_progress(op, rid):
    status, body = _json_req(
        op, BASE + "/api/course/{}/rollcalls".format(COURSE_ID))
    if status != 200 or not isinstance(body, dict):
        return None
    rows = body.get("rollcalls")
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and extract_rollcall_id(row) == str(rid):
            return str(row.get("status") or "") == "in_progress"
    return False


def _wait_rollcall_closed(op, rid, timeout_seconds=10.0):
    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while not STOP_EVENT.is_set() and time.monotonic() < deadline:
        state = _rollcall_in_progress(op, rid)
        if state is False:
            return True
        STOP_EVENT.wait(0.2)
    return False


def _save_rid(rid):
    _set(rollcall_id=rid)
    try:
        _write_json_atomic(
            RID_PATH,
            {"rollcall_id": rid, "saved_utc": _now_utc()},
            durable=True,
        )
    except OSError:
        pass


def _load_rid():
    rec = _read_json(RID_PATH)
    return str((rec or {}).get("rollcall_id") or "") if isinstance(rec, dict) else ""


def _write_token(data, rid, now_ms=None):
    try:
        timestamp = int(data[:10]) if isinstance(data, str) else None
    except ValueError:
        timestamp = None
    record = {
        "ok": True,
        "data": data,
        "ts": timestamp,
        "fetched_at_utc": _now_utc(),
        "rollcall_id": rid,
    }
    checked = validate_token_record(
        record, _utc_ms() if now_ms is None else now_ms, STALE_MS, FUTURE_SKEW_MS)
    if not checked.valid:
        raise RuntimeError("token rejected: {}".format(checked.error))
    _write_json_atomic(TOKEN_PATH, record, ensure_ascii=False)
    return checked



def _normalize_control_record(record):
    """Normalize legacy nonce or new versioned control records.

    Returns a canonical versioned dict or None. Accepts:
      - new: {"version":1,"cmd":"restart","request_id":...,"created_epoch_ms":...}
      - legacy: {"cmd":"restart","nonce":"<digits>"}
    Rejects arbitrary malformed records (missing keys, wrong types, or nonce/request_id not matching allowlisted patterns).
    """
    if not isinstance(record, dict) or record.get("cmd") != "restart":
        return None
    version = record.get("version")
    if isinstance(version, int) and not isinstance(version, bool) and version == 1:
        request_id = record.get("request_id")
        created = record.get("created_epoch_ms")
        if not isinstance(request_id, str) or CONTROL_REQUEST_ID_RE.fullmatch(request_id) is None:
            return None
        if isinstance(created, bool) or not isinstance(created, int) or created <= 0:
            return None
        return {
            "version": 1,
            "cmd": "restart",
            "request_id": request_id,
            "created_epoch_ms": created,
        }
    if version is None:
        nonce = record.get("nonce")
        if not isinstance(nonce, str) or LEGACY_NONCE_RE.fullmatch(nonce) is None:
            return None
        # Nonce-only legacy record: normalize to versioned form using nonce as request_id.
        try:
            created = int(nonce)
        except (TypeError, ValueError):
            return None
        if created <= 0:
            return None
        return {
            "version": 1,
            "cmd": "restart",
            "request_id": nonce,
            "created_epoch_ms": created,
        }
    return None


def _control_request():
    return _normalize_control_record(_read_json(CONTROL_PATH))


def _control_ack():
    record = _read_json(CONTROL_ACK_PATH)
    return record if isinstance(record, dict) else None


def _restart_request_pending():
    request = _control_request()
    if request is None:
        return None
    ack = _control_ack()
    if isinstance(ack, dict) and ack.get("request_id") == request["request_id"] \
            and ack.get("status") in {"completed", "rejected_preserve", "failed"}:
        return None
    return request


def _write_control_ack(request, status, *, rollcall_id="", error=""):
    if status not in {"accepted", "completed", "rejected_preserve", "failed"}:
        raise ValueError("invalid control ack status")
    record = {
        "version": 1,
        "request_id": request["request_id"],
        "status": status,
        "updated_utc": _now_utc(),
    }
    if rollcall_id:
        record["rollcall_id"] = str(rollcall_id)
    if error:
        record["error"] = str(error)[:80]
    _write_json_atomic(
        CONTROL_ACK_PATH,
        record,
        durable=True,
        separators=(",", ":"),
    )
    return record


def _restart_rollcall(op, rid, request):
    """Stop the current source, confirm closure, and create a distinct replacement."""
    try:
        _write_control_ack(request, "accepted", rollcall_id=rid)
        old_rid = str(rid or "")
        if old_rid:
            state = _rollcall_in_progress(op, old_rid)
            if state is None:
                _write_control_ack(request, "failed", error="status_unavailable")
                return rid, None
            if state:
                if not stop_rollcall(op, old_rid):
                    _write_control_ack(request, "failed", error="stop_failed")
                    return rid, None
                if not _wait_rollcall_closed(op, old_rid):
                    _write_control_ack(request, "failed", error="close_timeout")
                    return rid, None
        new_rid = create_rollcall(op)
        if not new_rid or new_rid == old_rid:
            _write_control_ack(request, "failed", error="replacement_not_created")
            return "", None
        _save_rid(new_rid)
        with LOCK:
            STATE["recreated"] = STATE.get("recreated", 0) + 1
        return new_rid, {"request": request, "old_rollcall_id": old_rid}
    except Exception as exc:
        try:
            _write_control_ack(
                request,
                "failed",
                error=_http_error_summary(exc),
            )
        except OSError:
            pass
        return "", None


class Corpus:
    """Opt-in daily gzip JSONL corpus with age, size, and free-space bounds."""

    def __init__(self):
        self.f = None
        self.path = ""
        self.day = ""
        self.bytes = 0
        self.pending = 0
        self.disabled = not CORPUS_ENABLED
        if self.disabled:
            _set(corpus_bytes=0)

    def disable(self):
        self.disabled = True
        self.close()
        _set(corpus_bytes=0)

    def close(self):
        if self.f is not None:
            try:
                self.f.flush()
            finally:
                self.f.close()
                self.f = None

    @staticmethod
    def _files():
        files = []
        for filename in os.listdir(WORKDIR):
            if re.fullmatch(r"tokens-\d{8}\.jsonl\.gz", filename):
                path = os.path.join(WORKDIR, filename)
                try:
                    files.append((filename, path, os.path.getsize(path)))
                except OSError:
                    continue
        return sorted(files)

    def _prune(self, protected_path=""):
        files = self._files()
        cutoff = time.strftime(
            "%Y%m%d",
            time.gmtime(time.time() - max(0, CORPUS_MAX_DAYS - 1) * 86400),
        )
        for filename, path, _size in list(files):
            day = filename[7:15]
            if day < cutoff:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    files.remove((filename, path, _size))
                    continue
                except (PermissionError, OSError):
                    raise
                files.remove((filename, path, _size))
        total = sum(size for _filename, _path, size in files)
        for item in list(files):
            if total <= CORPUS_MAX_BYTES:
                break
            _filename, path, size = item
            if protected_path and os.path.abspath(path) == os.path.abspath(protected_path):
                continue
            try:
                os.remove(path)
            except FileNotFoundError:
                files.remove(item)
                continue
            except (PermissionError, OSError):
                raise
            total -= size
            files.remove(item)
        return total

    def _open_day(self):
        self.close()
        self._prune()
        self.day = time.strftime("%Y%m%d", time.gmtime())
        self.path = os.path.join(WORKDIR, "tokens-{}.jsonl.gz".format(self.day))
        self.f = gzip.open(self.path, "at", encoding="utf-8")
        self.bytes = os.path.getsize(self.path)
        self.pending = 0

    def _flush_and_bound(self):
        self.f.flush()
        self.pending = 0
        current_size = os.path.getsize(self.path)
        total = self._prune(protected_path=self.path)
        if current_size > CORPUS_MAX_BYTES or total > CORPUS_MAX_BYTES:
            self.close()
            try:
                os.remove(self.path)
            except OSError:
                pass
            self.disable()
            return False
        self.bytes = current_size
        _set(corpus_bytes=total)
        return True

    def write(self, line):
        if self.disabled:
            return
        # Allow a bounded prune/recheck before declining due to low space.
        if shutil.disk_usage(WORKDIR).free < CORPUS_MIN_FREE_BYTES:
            try:
                total = self._prune(protected_path=self.path if self.path else "")
            except (PermissionError, OSError):
                self.disable()
                _set(corpus_bytes=0)
                print("corpus disabled: prune failed", flush=True)
                return
            if shutil.disk_usage(WORKDIR).free < CORPUS_MIN_FREE_BYTES:
                _set(corpus_bytes=total)
                return
        if self.f is None or self.day != time.strftime("%Y%m%d", time.gmtime()):
            self._open_day()
        self.f.write(line + "\n")
        self.pending += 1
        if self.pending >= CORPUS_FLUSH_RECORDS:
            self._flush_and_bound()


def harvester():
    op = None
    jar = None
    rid = _load_rid()
    backoff = 1.0
    corpus = Corpus()
    last_cookie_save = 0.0
    last_meta_rid = ""
    previous_preserve = False
    restart_pending = None
    try:
        while not STOP_EVENT.is_set():
            preserve = preserve_active()
            _set(preserve=preserve)
            try:
                if preserve and not previous_preserve and jar is not None:
                    _save_jar_atomic(jar, COOKIE_PATH)
                    last_cookie_save = time.time()
                previous_preserve = preserve

                if op is None:
                    jar = _load_jar(COOKIE_PATH)
                    op = _opener(jar)
                    if not preserve and not session_valid(op):
                        op = login(TEACHER_USER, TEACHER_PASS, jar)
                        _save_jar_atomic(jar, COOKIE_PATH)
                        with LOCK:
                            STATE["logins"] = STATE.get("logins", 0) + 1
                            STATE["session_since_utc"] = _now_utc()
                            STATE["last_error"] = ""
                        last_cookie_save = time.time()

                if not rid:
                    rid = live_qr_rollcall(op)
                    if not rid:
                        rid = create_rollcall(op)
                        with LOCK:
                            STATE["recreated"] = STATE.get("recreated", 0) + 1
                    if rid:
                        _save_rid(rid)

                request = _restart_request_pending()
                request_id = request.get("request_id") if isinstance(request, dict) else ""
                pending_id = restart_pending["request"]["request_id"] \
                    if isinstance(restart_pending, dict) else ""
                if request_id and request_id != pending_id:
                    if preserve:
                        _write_control_ack(
                            request,
                            "rejected_preserve",
                            rollcall_id=rid,
                        )
                    else:
                        rid, restart_pending = _restart_rollcall(op, rid, request)
                        last_meta_rid = ""
                        if not rid:
                            raise RuntimeError("restart source recovery pending")

                if rid and rid != last_meta_rid and _record_rollcall_meta(op, rid):
                    last_meta_rid = rid

                status, body = _json_req(
                    op, BASE + "/api/course/{}/rollcall/{}/qr_code".format(COURSE_ID, rid))
                data = str((body or {}).get("data") or "") if isinstance(body, dict) else ""
                if status != 200:
                    raise RuntimeError("qr_code invalid response (HTTP {})".format(status))
                checked = _write_token(data, rid)
                ts = checked.timestamp
                with LOCK:
                    STATE.update(last_fetch_utc=_now_utc(), age_ms=checked.age_ms,
                                 rollcall_id=rid, ok=True, last_error="")
                if isinstance(restart_pending, dict):
                    _write_control_ack(
                        restart_pending["request"],
                        "completed",
                        rollcall_id=rid,
                    )
                    restart_pending = None
                try:
                    corpus.write(json.dumps(
                        {"utc": _now_utc(), "ts": ts, "data": data}, separators=(",", ":")))
                except Exception as exc:
                    corpus.disable()
                    _set(corpus_bytes=0)
                    print("corpus disabled: {}".format(type(exc).__name__), flush=True)

                if not preserve and jar is not None and \
                        time.time() - last_cookie_save > COOKIE_RESAVE_SECONDS:
                    try:
                        _save_jar_atomic(jar, COOKIE_PATH)
                        last_cookie_save = time.time()
                    except OSError:
                        pass

                backoff = 1.0
                STOP_EVENT.wait(POLL_SECONDS)
            except Exception as exc:
                msg = _http_error_summary(exc)
                _set(ok=False, last_error=msg)
                if preserve:
                    _set(preserve_alert=_now_utc())
                print("harvest error: {} (backoff {}s, preserve={})".format(
                    msg, backoff, preserve), flush=True)
                recoverable = False
                try:
                    raise exc
                except AuthenticationLost:
                    op = None
                    rid = ""
                    recoverable = True
                except urllib.error.HTTPError as http_exc:
                    if http_exc.code in (401, 403):
                        op = None
                        rid = ""
                        recoverable = True
                    else:
                        pass
                except (OSError, urllib.error.URLError):
                    recoverable = True
                except Exception:
                    pass
                if not recoverable:
                    try:
                        if op is not None and rid and not live_qr_rollcall(op):
                            rid = ""
                            recoverable = True
                    except AuthenticationLost:
                        op = None
                        rid = ""
                        recoverable = True
                    except (OSError, urllib.error.URLError):
                        op = None
                        recoverable = True
                    except Exception:
                        pass
                if not recoverable:
                    # Non-auth, non-network: keep harvester alive via backoff without crashing.
                    _set(ok=False, last_error=msg)
                STOP_EVENT.wait(backoff)
                backoff = min(backoff * 2, 60.0)
    finally:
        corpus.close()


def passive_check():
    """Passively validate the local token file without any network mutation."""
    while not STOP_EVENT.is_set():
        record = _read_json(TOKEN_PATH)
        checked = validate_token_record(
            record, _utc_ms(), STALE_MS, FUTURE_SKEW_MS)
        result = {"utc": _now_utc(), "ok": checked.valid,
                  "age_ms": checked.age_ms}
        if not checked.valid:
            result["error"] = checked.error
        _set(passive_check_last=result)
        STOP_EVENT.wait(PASSIVE_CHECK_SECONDS)


def state_writer():
    while not STOP_EVENT.is_set():
        try:
            _write_json_atomic(STATE_PATH, _get(), ensure_ascii=False)
        except OSError as exc:
            print("state write error: {}".format(type(exc).__name__), flush=True)
        STOP_EVENT.wait(STATE_WRITE_SECONDS)


def _request_stop(signum, frame):
    del signum, frame
    STOP_EVENT.set()


def _run_supervised(name, target):
    try:
        target()
    except BaseException as exc:
        _set(ok=False, last_error="{}_stopped".format(name))
        print("{} stopped: {}".format(name, type(exc).__name__), flush=True)
    finally:
        if not STOP_EVENT.is_set():
            STOP_EVENT.set()


def main():
    config = load_config()
    apply_config(config)
    socket.setdefaulttimeout(SOCKET_TIMEOUT_SECONDS)
    os.makedirs(WORKDIR, mode=0o700, exist_ok=True)
    STOP_EVENT.clear()
    _set(started_utc=_now_utc(), ok=False, last_error="",
         source_revision=SOURCE_REVISION)
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    threads = [
        threading.Thread(
            target=_run_supervised,
            args=("harvester", harvester),
            name="harvester",
        ),
        threading.Thread(
            target=_run_supervised,
            args=("passive_check", passive_check),
            name="passive-check",
        ),
        threading.Thread(
            target=_run_supervised,
            args=("state_writer", state_writer),
            name="state-writer",
        ),
    ]
    for thread in threads:
        thread.start()
    try:
        STOP_EVENT.wait()
    except KeyboardInterrupt:
        STOP_EVENT.set()
    finally:
        STOP_EVENT.set()
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    main()
