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
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Optional

from qr_common import ConfigError, env_choice, env_float, env_int, env_text
from qr_common import env_utc_date, validate_token_record
from qr_common import write_json_atomic as _write_json_atomic


@dataclass(frozen=True)
class KeeperConfig:
    base: str
    course_id: str
    teacher_user: str
    teacher_pass: str
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


class AuthenticationLost(RuntimeError):
    """The teacher session is no longer authenticated."""


def load_config(env: Optional[Mapping[str, str]] = None) -> KeeperConfig:
    values = os.environ if env is None else env
    base = env_text(values, "QR_BASE", "https://www.tronclass.com.tw", required=True).rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in ("http", "https") or not parsed.hostname \
            or parsed.username is not None or parsed.password is not None:
        raise ConfigError("QR_BASE must be an http(s) origin without credentials")
    course_id = str(env_int(values, "QR_COURSE_ID", 0, minimum=1))
    preserve_mode = env_choice(
        values, "QR_PRESERVE_MODE", "auto", ("on", "off", "auto"))
    preserve_after = env_utc_date(
        values, "QR_PRESERVE_AFTER", required=(preserve_mode == "auto"))
    duration = env_text(values, "QR_ROLLCALL_DURATION_SECONDS", default="")
    if duration and (not duration.isdigit() or int(duration) <= 0):
        raise ConfigError("QR_ROLLCALL_DURATION_SECONDS must be a positive integer")
    return KeeperConfig(
        base=base,
        course_id=course_id,
        teacher_user=env_text(values, "QR_TEACHER_USER", required=True),
        teacher_pass=env_text(values, "QR_TEACHER_PASS", required=True),
        poll_seconds=env_float(values, "QR_POLL_SECONDS", 0.5,
                               minimum=0.0, minimum_exclusive=True),
        workdir=env_text(values, "QR_WORKDIR", "/home/opc/qr-harvest", required=True),
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
            minimum=0.0, minimum_exclusive=True, maximum=300.0),
    )


BASE = "https://www.tronclass.com.tw"
COURSE_ID = ""
TEACHER_USER = ""
TEACHER_PASS = ""
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

COOKIE_PATH = os.path.join(WORKDIR, "cookies.txt")
TOKEN_PATH = os.path.join(WORKDIR, "token.json")
STATE_PATH = os.path.join(WORKDIR, "state.json")
CONTROL_PATH = os.path.join(WORKDIR, "control.json")
RID_PATH = os.path.join(WORKDIR, "rollcall.json")

FORM_JSON_RE = re.compile(r":email-login-form\s*=\s*(['\"])(.*?)\1", re.S)
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
    global BASE, COURSE_ID, TEACHER_USER, TEACHER_PASS, POLL_SECONDS, WORKDIR
    global PASSIVE_CHECK_SECONDS, STATE_WRITE_SECONDS, COOKIE_RESAVE_SECONDS
    global _ROLLCALL_DURATION_ENV, PRESERVE_MODE, PRESERVE_AFTER
    global STALE_MS, FUTURE_SKEW_MS, SOCKET_TIMEOUT_SECONDS
    global COOKIE_PATH, TOKEN_PATH, STATE_PATH, CONTROL_PATH, RID_PATH
    BASE = config.base
    COURSE_ID = config.course_id
    TEACHER_USER = config.teacher_user
    TEACHER_PASS = config.teacher_pass
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
    COOKIE_PATH = os.path.join(WORKDIR, "cookies.txt")
    TOKEN_PATH = os.path.join(WORKDIR, "token.json")
    STATE_PATH = os.path.join(WORKDIR, "state.json")
    CONTROL_PATH = os.path.join(WORKDIR, "control.json")
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
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
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
    tmp = path + ".tmp"
    jar.save(filename=tmp, ignore_discard=True, ignore_expires=True)
    os.replace(tmp, path)


def _opener(jar):
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _json_req(op, url, payload=None, method=None):
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with op.open(req) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = getattr(resp, "status", 200)
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read().decode("utf-8", "replace")
    try:
        return status, json.loads(raw)
    except (TypeError, ValueError):
        return status, None


def session_valid(op):
    try:
        check = op.open(BASE + "/api/my-courses").read().decode("utf-8", "replace")
        return '"courses"' in check
    except (OSError, urllib.error.URLError, ValueError):
        return False


def login(user, passwd, jar):
    """Open a teacher email session and keep cookies in the supplied jar."""
    op = _opener(jar)
    page = op.open(BASE + "/login").read().decode("utf-8", "replace")
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
    op.open(req).read()
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
        _json_req(op, BASE + "/api/rollcall/{}/start-rollcall".format(rid),
                  {"duration": duration} if duration > 0 else None, "POST")
        _set(rollcall_duration=duration)
        return rid
    raise RuntimeError("create rollcall failed (HTTP {})".format(last_status))


def _record_rollcall_meta(op, rid):
    try:
        for row in list_rollcalls(op):
            if str(row.get("id")) == str(rid):
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
            return str(row.get("id") or "")
    return ""


def stop_rollcall(op, rid):
    _json_req(op, BASE + "/api/rollcall/{}/stop_qr_rollcall".format(rid),
              payload=None, method="PUT")


def _save_rid(rid):
    _set(rollcall_id=rid)
    try:
        _write_json_atomic(RID_PATH, {"rollcall_id": rid, "saved_utc": _now_utc()})
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


def _control_nonce():
    rec = _read_json(CONTROL_PATH)
    return str((rec or {}).get("nonce") or "") if isinstance(rec, dict) else ""


class Corpus:
    """Daily rotating gzip JSONL corpus with bounded storage."""

    def __init__(self):
        self.f = None
        self.day = ""
        self.bytes = 0
        self.pending = 0

    def close(self):
        if self.f is not None:
            try:
                self.f.flush()
            finally:
                self.f.close()
                self.f = None

    def _prune(self):
        files = sorted(f for f in os.listdir(WORKDIR)
                       if re.fullmatch(r"tokens-\d{8}\.jsonl\.gz", f))
        total = sum(os.path.getsize(os.path.join(WORKDIR, f)) for f in files)
        for filename in list(files):
            if total <= 15 * 1024 ** 3 or len(files) == 1:
                break
            path = os.path.join(WORKDIR, filename)
            total -= os.path.getsize(path)
            os.remove(path)
            files.remove(filename)

    def _open_day(self):
        self.close()
        self._prune()
        self.day = time.strftime("%Y%m%d", time.gmtime())
        path = os.path.join(WORKDIR, "tokens-{}.jsonl.gz".format(self.day))
        self.f = gzip.open(path, "at", encoding="utf-8")
        self.bytes = os.path.getsize(path)
        self.pending = 0

    def write(self, line):
        if self.f is None or self.day != time.strftime("%Y%m%d", time.gmtime()):
            self._open_day()
        if shutil.disk_usage(WORKDIR).free < 5 * 1024 ** 3:
            return
        self.f.write(line + "\n")
        self.bytes += len(line.encode("utf-8")) + 1
        self.pending += 1
        if self.pending >= 20:
            self.f.flush()
            self.pending = 0
        _set(corpus_bytes=self.bytes)


def harvester():
    op = None
    jar = None
    rid = _load_rid()
    backoff = 1.0
    corpus = Corpus()
    last_cookie_save = 0.0
    last_ctrl = _control_nonce()
    last_meta_rid = ""
    try:
        while not STOP_EVENT.is_set():
            preserve = preserve_active()
            _set(preserve=preserve)
            try:
                ctrl = _control_nonce()
                if ctrl != last_ctrl:
                    last_ctrl = ctrl
                    if not preserve and op is not None and rid:
                        try:
                            stop_rollcall(op, rid)
                        except (OSError, urllib.error.URLError):
                            pass
                        rid = ""

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
                corpus.write(json.dumps(
                    {"utc": _now_utc(), "ts": ts, "data": data}, separators=(",", ":")))

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
                auth_loss = (isinstance(exc, urllib.error.HTTPError)
                             and exc.code in (401, 403)) \
                    or isinstance(exc, AuthenticationLost)
                if auth_loss:
                    op = None
                    rid = ""
                else:
                    try:
                        if op is not None and rid and not live_qr_rollcall(op):
                            rid = ""
                    except (OSError, urllib.error.URLError):
                        op = None
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


def main():
    config = load_config()
    apply_config(config)
    socket.setdefaulttimeout(SOCKET_TIMEOUT_SECONDS)
    os.makedirs(WORKDIR, mode=0o700, exist_ok=True)
    STOP_EVENT.clear()
    _set(started_utc=_now_utc(), ok=False, last_error="")
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    threads = [
        threading.Thread(target=harvester, name="harvester"),
        threading.Thread(target=passive_check, name="passive-check"),
        threading.Thread(target=state_writer, name="state-writer"),
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
