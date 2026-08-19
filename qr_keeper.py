#!/usr/bin/env python3
"""TronClass 公有雲 QR 點名 data 採集 keeper（純 stdlib，Python 3.9+）。

保持一場 in_progress QR 點名，每 POLL_SECONDS 輪詢 qr_code 端點採集當下 data。設計重點：
- Cookie 落地：教師/學生 session cookie 原子寫入磁碟（LWPCookieJar），啟動載入重用；
  只有在沒有有效 cookie 時才 login，任何進程重啟都不重登。
- 單一長效點名：開場 duration 取伺服器上限（end_time 卡 9999 年 datetime 天花板）；預設每次
  建場動態算「到 9999-01-01」＝當下最大，只有點名真的結束才重建（fallback）。
- 對外 API 已拆出（qr_api.py 獨立進程），本檔每 poll 原子寫 token.json（供 API 讀），
  並輪詢 control.json 收「重建點名」指令。
- 全量語料 tokens-YYYYMMDD.jsonl.gz（每日輪轉、容量上限、低磁碟時停寫語料不影響採集）。
- 每 SELFTEST_SECONDS 以學生帳號用最新 token 實答做端到端活性檢查；每 LOGINPROBE_SECONDS
  以拋棄式 jar 全新登入做對照（不碰主 cookie）。
零第三方依賴。環境變數見 secrets.env。
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
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("QR_BASE", "https://www.tronclass.com.tw").rstrip("/")
COURSE_ID = os.environ.get("QR_COURSE_ID", "55379")
TEACHER_USER = os.environ.get("QR_TEACHER_USER", "")
TEACHER_PASS = os.environ.get("QR_TEACHER_PASS", "")
STUDENT_USER = os.environ.get("QR_STUDENT_USER", "")
STUDENT_PASS = os.environ.get("QR_STUDENT_PASS", "")
POLL_SECONDS = float(os.environ.get("QR_POLL_SECONDS", "0.5"))
WORKDIR = os.environ.get("QR_WORKDIR", "/home/opc/qr-harvest")
SELFTEST_SECONDS = float(os.environ.get("QR_SELFTEST_SECONDS", "3600"))
LOGINPROBE_SECONDS = float(os.environ.get("QR_LOGINPROBE_SECONDS", "21600"))
STATE_WRITE_SECONDS = float(os.environ.get("QR_STATE_WRITE_SECONDS", "5"))
COOKIE_RESAVE_SECONDS = float(os.environ.get("QR_COOKIE_RESAVE_SECONDS", "300"))
# 一直沿用同一場點名：開場 duration 拉到伺服器上限。實測上限＝rollcall end_time 卡在 DB 的
# 9999 年 datetime 天花板（約 7978 年；超過即 500 溢位）。預設每次建場動態算「到 9999-01-01」
# ＝當下最大值（留 ~11 個月餘裕避免溢位）。QR_ROLLCALL_DURATION_SECONDS 設正整數可覆寫。
_ROLLCALL_DURATION_ENV = os.environ.get("QR_ROLLCALL_DURATION_SECONDS", "").strip()

COOKIE_PATH = os.path.join(WORKDIR, "cookies.txt")
STUDENT_COOKIE_PATH = os.path.join(WORKDIR, "cookies-student.txt")
TOKEN_PATH = os.path.join(WORKDIR, "token.json")
STATE_PATH = os.path.join(WORKDIR, "state.json")
CONTROL_PATH = os.path.join(WORKDIR, "control.json")
RID_PATH = os.path.join(WORKDIR, "rollcall.json")

TOKEN_RE = re.compile(r"\d{10}[0-9a-f]{32}")
FORM_JSON_RE = re.compile(r":email-login-form\s*=\s*(['\"])(.*?)\1", re.S)
HIDDEN_RE = re.compile(r"email-login-hidden-tag\s*=\s*(['\"])(.*?)\1", re.S)

socket.setdefaulttimeout(20)
os.umask(0o077)

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
    "self_test_last": {},
    "login_probe_last": {},
    "corpus_bytes": 0,
    "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
LOCK = threading.Lock()


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
        try:
            body = exc.read(200).decode("utf-8", "replace")
        except Exception:
            body = ""
        return "HTTP {} {}".format(exc.code, body[:120])
    return "{}: {}".format(type(exc).__name__, exc)


def _write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def preserve_active():
    """preserve 模式是否啟用。QR_PRESERVE_MODE=on|off|auto（預設 auto）；
    auto 時當 UTC 日期 >= QR_PRESERVE_AFTER（YYYY-MM-DD）即自動啟用。"""
    mode = os.environ.get("QR_PRESERVE_MODE", "auto").strip().lower()
    if mode == "on":
        return True
    if mode == "off":
        return False
    after = os.environ.get("QR_PRESERVE_AFTER", "").strip()
    if not after:
        return False
    return time.strftime("%Y-%m-%d", time.gmtime()) >= after


# --------------------------------------------------------------------------- #
# Cookie 持久化（LWPCookieJar；session cookie 是 discard cookie，兩旗標缺一不可）
# --------------------------------------------------------------------------- #
def _load_jar(path):
    jar = http.cookiejar.LWPCookieJar(path)
    if os.path.exists(path):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
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
    except ValueError:
        return status, raw


def session_valid(op):
    try:
        check = op.open(BASE + "/api/my-courses").read().decode("utf-8", "replace")
        return '"courses"' in check
    except Exception:
        return False


def login(user, passwd, jar):
    """公有雲 email 登入：GET /login -> 解析 email-login-form JSON 與 hidden 欄位 ->
    POST /login?login=email 表單編碼 -> GET /api/my-courses 驗證。cookie 落在傳入的 jar。"""
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
        except Exception:
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
        raise RuntimeError("login validation failed (no courses in /api/my-courses)")
    return op


# --------------------------------------------------------------------------- #
# Rollcall 生命週期
# --------------------------------------------------------------------------- #
def build_qr_payload(title):
    """建立一場 QR 點名（in_progress、type=qr_rollcall）的 payload。"""
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
    """從回應抽出 rollcall id：先看 id/rollcall_id/rollcallId，再遞迴巢狀 rollcall/data。"""
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
    """到 9999-01-01 的秒數＝伺服器可接受的最大 duration 上限（end_time 卡 9999 年天花板；留餘裕避免溢位）。"""
    try:
        return max(0, int(calendar.timegm((9999, 1, 1, 0, 0, 0, 0, 0, 0)) - time.time()))
    except Exception:
        return 157680000000  # ~5000y fallback


def _duration_ladder():
    if _ROLLCALL_DURATION_ENV.isdigit() and int(_ROLLCALL_DURATION_ENV) > 0:
        top = int(_ROLLCALL_DURATION_ENV)
    else:
        top = _max_rollcall_duration()
    return (top, 3153600000, 31536000, 2592000, 86400, 7200, 0)  # 上限→100y→1y→30d→1d→2h→預設


def create_rollcall(op):
    """建立並 start 一場 QR 點名，duration 拉到伺服器上限（~9999 年）。若被拒（500 溢位或無
    id），沿 ladder 退到較小值，確保一定建得起來。回傳 rid。點名的 end_time 由 harvester 的
    _record_rollcall_meta 寫進 STATE（/health 可見）。"""
    last = ""
    seen = set()
    for d in _duration_ladder():
        d = max(0, int(d))
        if d in seen:
            continue
        seen.add(d)
        payload = build_qr_payload(time.strftime("%Y.%m.%d %H:%M", time.gmtime()))
        payload["duration"] = d
        status, body = _json_req(
            op, BASE + "/api/course/{}/rollcall".format(COURSE_ID), payload)
        rid = extract_rollcall_id(body)
        if not rid:
            last = "HTTP {} {}".format(status, str(body)[:120])
            continue
        _json_req(op, BASE + "/api/rollcall/{}/start-rollcall".format(rid),
                  {"duration": d} if d > 0 else None, "POST")
        _set(rollcall_duration=d)
        return rid
    raise RuntimeError("create rollcall failed (all durations): {}".format(last))


def _record_rollcall_meta(op, rid):
    """從 rollcalls 列表撈當前點名的 end_time/status 寫進 STATE（/health 自報這場撐到何時）。
    end_time 只在列表回應出現、不在建場回應。回傳 True＝已找到並記錄；False＝列表尚未含此
    rid（最終一致性延遲），呼叫端應下輪重試，勿提前鎖定。"""
    try:
        for row in list_rollcalls(op):
            if str(row.get("id")) == str(rid):
                _set(rollcall_finished_at=str(row.get("end_time") or ""),
                     rollcall_status=str(row.get("status") or ""))
                return True
    except Exception:
        pass
    return False


def list_rollcalls(op):
    status, body = _json_req(op, BASE + "/api/course/{}/rollcalls".format(COURSE_ID))
    if status != 200 or not isinstance(body, dict):
        return []
    return body.get("rollcalls") or []


def live_qr_rollcall(op):
    for row in list_rollcalls(op):
        if str(row.get("status", "")) == "in_progress" and \
                str(row.get("type", "")) in ("qr_rollcall", "qr"):
            return str(row.get("id") or "")
    return ""


def stop_rollcall(op, rid):
    _json_req(op, BASE + "/api/rollcall/{}/stop_qr_rollcall".format(rid), payload=None, method="PUT")


def _save_rid(rid):
    _set(rollcall_id=rid)
    try:
        _write_json_atomic(RID_PATH, {"rollcall_id": rid, "saved_utc": _now_utc()})
    except Exception:
        pass


def _load_rid():
    rec = _read_json(RID_PATH)
    return str((rec or {}).get("rollcall_id") or "") if isinstance(rec, dict) else ""


def _write_token(data, ts, rid):
    _write_json_atomic(TOKEN_PATH, {
        "ok": True, "data": data, "ts": ts,
        "fetched_at_utc": _now_utc(), "rollcall_id": rid,
    })


def _control_nonce():
    rec = _read_json(CONTROL_PATH)
    return str((rec or {}).get("nonce") or "") if isinstance(rec, dict) else ""


# --------------------------------------------------------------------------- #
# 語料（每日輪轉 gzip JSONL）
# --------------------------------------------------------------------------- #
class Corpus:
    """每日輪轉的 gzip JSONL 語料檔；每 20 行 flush；總量 >15GB 刪最舊檔。"""

    def __init__(self):
        self.f = None
        self.day = ""
        self.bytes = 0
        self.pending = 0

    def _prune(self):
        files = sorted(f for f in os.listdir(WORKDIR)
                       if re.fullmatch(r"tokens-\d{8}\.jsonl\.gz", f))
        total = sum(os.path.getsize(os.path.join(WORKDIR, f)) for f in files)
        for f in list(files):
            if total <= 15 * 1024 ** 3 or len(files) == 1:
                break
            path = os.path.join(WORKDIR, f)
            total -= os.path.getsize(path)
            os.remove(path)
            files.remove(f)

    def _open_day(self):
        if self.f:
            self.f.close()
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


# --------------------------------------------------------------------------- #
# Harvester 主迴圈（normal / preserve 兩種規制）
# --------------------------------------------------------------------------- #
def harvester():
    op = None
    jar = None
    rid = _load_rid()
    backoff = 1.0
    corpus = Corpus()
    last_cookie_save = 0.0
    last_ctrl = _control_nonce()
    last_meta_rid = ""
    while True:
        preserve = preserve_active()
        _set(preserve=preserve)
        try:
            # 控制檔：重建點名（preserve 模式不主動重建，忽略）
            ctrl = _control_nonce()
            if ctrl != last_ctrl:
                last_ctrl = ctrl
                if not preserve and op is not None and rid:
                    try:
                        stop_rollcall(op, rid)
                    except Exception:
                        pass
                    rid = ""

            # 確保 opener：一律從磁碟重載凍結 cookie
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

            # 確保 rollcall（點名約 2h 自動 is_finished，兩模式都需以 cookie 重建；
            # preserve 差別只在「絕不 login」，create/poll 仍用凍結 cookie 續命）
            if not rid:
                rid = live_qr_rollcall(op)
                if not rid:
                    rid = create_rollcall(op)
                    with LOCK:
                        STATE["recreated"] = STATE.get("recreated", 0) + 1
                if rid:
                    _save_rid(rid)

            # rid 變動時（含開機從磁碟載入）查列表記錄 end_time/status；查不到（列表延遲）下輪重試
            if rid and rid != last_meta_rid:
                if _record_rollcall_meta(op, rid):
                    last_meta_rid = rid

            # 輪詢 qr_code
            status, body = _json_req(
                op, BASE + "/api/course/{}/rollcall/{}/qr_code".format(COURSE_ID, rid))
            data = str((body or {}).get("data") or "") if isinstance(body, dict) else ""
            if status != 200 or not TOKEN_RE.fullmatch(data):
                raise RuntimeError("qr_code bad: HTTP {} body {}".format(status, str(body)[:120]))
            ts = int(data[:10])
            age_ms = _utc_ms() - ts * 1000
            with LOCK:
                STATE.update(last_fetch_utc=_now_utc(), age_ms=age_ms,
                             rollcall_id=rid, ok=True, last_error="")
            _write_token(data, ts, rid)
            corpus.write(json.dumps({"utc": _now_utc(), "ts": ts, "data": data}))

            # 週期回存 cookie（normal 模式；preserve 凍結磁碟 cookie 不覆寫）
            if not preserve and jar is not None and \
                    time.time() - last_cookie_save > COOKIE_RESAVE_SECONDS:
                try:
                    _save_jar_atomic(jar, COOKIE_PATH)
                    last_cookie_save = time.time()
                except Exception:
                    pass

            backoff = 1.0
            time.sleep(POLL_SECONDS)
        except Exception as exc:
            msg = _http_error_summary(exc)
            _set(ok=False, last_error=msg)
            if preserve:
                _set(preserve_alert=_now_utc())
            print("harvest error: {} (backoff {}s, preserve={})".format(msg, backoff, preserve),
                  flush=True)
            auth_loss = (isinstance(exc, urllib.error.HTTPError) and exc.code in (401, 403)) \
                or "login validation failed" in msg
            if auth_loss:
                # normal：丟 session、下輪重登。preserve：op=None 只重載凍結 cookie，
                # 絕不 login、絕不刪 cookie（下輪以凍結 cookie 重建/重試）。
                op = None
                rid = ""
            else:
                # 非 auth（多為點名已 is_finished）→ 清 rid，下輪以 cookie 重建（兩模式同）。
                try:
                    if op is not None and rid and not live_qr_rollcall(op):
                        rid = ""
                except Exception:
                    op = None
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)


def self_test():
    """每 SELFTEST_SECONDS 以學生帳號將最新 token 實答點名——整條鏈的活性證明。
    學生 session 亦落地（cookies-student.txt）；preserve 模式下不驗證/不重登，直接以既有
    cookie 試答。"""
    while True:
        try:
            tok = _read_json(TOKEN_PATH) or {}
            data = tok.get("data") or ""
            rid = tok.get("rollcall_id") or ""
            if data and rid:
                jar = _load_jar(STUDENT_COOKIE_PATH)
                op = _opener(jar)
                if not preserve_active() and not session_valid(op):
                    op = login(STUDENT_USER, STUDENT_PASS, jar)
                    _save_jar_atomic(jar, STUDENT_COOKIE_PATH)
                status, body = _json_req(
                    op, BASE + "/api/rollcall/{}/answer_qr_rollcall".format(rid),
                    {"data": data, "deviceId": "qr-harvest-selftest"}, method="PUT")
                _set(self_test_last={"utc": _now_utc(), "http": status,
                                     "body": str(body)[:160], "preserve": preserve_active()})
        except Exception as exc:
            _set(self_test_last={"utc": _now_utc(), "error": _http_error_summary(exc)})
        time.sleep(SELFTEST_SECONDS)


def login_probe():
    """每 LOGINPROBE_SECONDS 一次全新登入作為對照。
    用拋棄式 in-memory jar，絕不碰主 cookie 檔。"""
    while True:
        try:
            login(TEACHER_USER, TEACHER_PASS, http.cookiejar.LWPCookieJar())
            _set(login_probe_last={"utc": _now_utc(), "ok": True})
        except Exception as exc:
            _set(login_probe_last={"utc": _now_utc(), "ok": False,
                                   "error": _http_error_summary(exc)})
        time.sleep(LOGINPROBE_SECONDS)


def state_writer():
    """每 STATE_WRITE_SECONDS 原子寫 state.json（健康面；不含 token，/health 無驗證）。"""
    while True:
        try:
            st = _get()
            st.pop("last_data", None)  # 安全：token 只走 token.json（Bearer），絕不進 /health
            _write_json_atomic(STATE_PATH, st)
        except Exception as exc:
            print("state write error: {}".format(exc), flush=True)
        time.sleep(STATE_WRITE_SECONDS)


def main():
    os.makedirs(WORKDIR, exist_ok=True)
    for fn, name in ((harvester, "harvester"), (self_test, "self-test"),
                     (login_probe, "login-probe"), (state_writer, "state-writer")):
        threading.Thread(target=fn, name=name, daemon=True).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
