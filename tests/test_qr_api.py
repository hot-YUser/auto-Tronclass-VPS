import hashlib
import http.client
import json
import pathlib
import tempfile
import threading
import time
import unittest

import qr_api
from qr_common import ConfigError


class FakeClock:
    def __init__(self, value=0.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


class TokenBucketTests(unittest.TestCase):
    def test_deterministic_refill_and_retry_after(self):
        clock = FakeClock()
        table = qr_api.TokenBucketTable(1.0, 2, 8, clock)
        self.assertEqual((True, 0.0), table.consume("a"))
        self.assertEqual((True, 0.0), table.consume("a"))
        allowed, retry = table.consume("a")
        self.assertFalse(allowed)
        self.assertAlmostEqual(1.0, retry)
        clock.advance(0.5)
        allowed, retry = table.consume("a")
        self.assertFalse(allowed)
        self.assertAlmostEqual(0.5, retry)
        clock.advance(0.5)
        self.assertEqual((True, 0.0), table.consume("a"))

    def test_limiter_table_is_bounded(self):
        table = qr_api.TokenBucketTable(1.0, 1, 2, FakeClock())
        for key in ("a", "b", "c", "d"):
            table.consume(key)
        self.assertEqual(2, table.size)

    def test_one_request_per_second_remains_compatible(self):
        clock = FakeClock()
        env = api_env("/tmp/qr-api-rate")
        env.update({"QR_PRINCIPAL_RATE": "1", "QR_PRINCIPAL_BURST": "1"})
        limiter = qr_api.RequestLimiter(qr_api.load_config(env), clock)
        self.assertTrue(limiter.check("/token", "client")[0])
        clock.advance(1.0)
        self.assertTrue(limiter.check("/token", "client")[0])


class BoundedExecutorTests(unittest.TestCase):
    def test_worker_and_pending_capacity_is_strict(self):
        started = threading.Event()
        release = threading.Event()
        completed = []

        def blocking(value):
            started.set()
            release.wait(2)
            completed.append(value)

        executor = qr_api.BoundedExecutor(1, 1, name="test")
        try:
            self.assertTrue(executor.submit(blocking, "running"))
            self.assertTrue(started.wait(1))
            self.assertTrue(executor.submit(blocking, "pending"))
            self.assertFalse(executor.submit(blocking, "rejected"))
            self.assertEqual(1, executor.worker_count)
            self.assertEqual(1, executor.pending_count)
        finally:
            release.set()
            executor.shutdown()
        self.assertEqual(["running", "pending"], completed)


def api_env(workdir):
    return {
        "QR_API_KEY": "master-secret-value",
        "QR_BIND": "127.0.0.1",
        "QR_PORT": "8741",
        "QR_WORKDIR": workdir,
        "QR_STALE_MS": "500",
        "QR_FUTURE_SKEW_MS": "500",
        "QR_API_WORKERS": "2",
        "QR_API_PENDING": "4",
        "QR_SOCKET_TIMEOUT_SECONDS": "2",
        "QR_LIMITER_MAX_ENTRIES": "32",
        "QR_GLOBAL_RATE": "1000",
        "QR_GLOBAL_BURST": "1000",
        "QR_PRINCIPAL_RATE": "1000",
        "QR_PRINCIPAL_BURST": "1000",
        "QR_HEALTH_RATE": "1000",
        "QR_HEALTH_BURST": "1000",
        "QR_RESTART_RATE": "1000",
        "QR_RESTART_BURST": "1000",
    }


class ApiConfigTests(unittest.TestCase):
    def test_config_rejects_placeholders_empty_values_and_bad_intervals(self):
        cases = []
        env = api_env("/tmp/qr-api")
        env["QR_API_KEY"] = "<replace-with-secret>"
        cases.append(env)
        env = api_env("/tmp/qr-api")
        env["QR_WORKDIR"] = ""
        cases.append(env)
        for key in ("QR_SOCKET_TIMEOUT_SECONDS", "QR_GLOBAL_RATE",
                    "QR_PRINCIPAL_RATE", "QR_HEALTH_RATE", "QR_RESTART_RATE"):
            env = api_env("/tmp/qr-api")
            env[key] = "0"
            cases.append(env)
        env = api_env("/tmp/qr-api")
        env["QR_PORT"] = "70000"
        cases.append(env)
        for env in cases:
            with self.subTest(env=env), self.assertRaises(ConfigError):
                qr_api.load_config(env)

    def test_master_key_may_be_omitted_for_managed_keys(self):
        env = api_env("/tmp/qr-api")
        env["QR_API_KEY"] = ""
        self.assertEqual("", qr_api.load_config(env).api_key)


class ApiServerTests(unittest.TestCase):
    NOW = 2_000_000_000.5
    DATA = "2000000000" + "a" * 32
    SECURITY = {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
        "cross-origin-resource-policy": "same-origin",
        "vary": "Authorization",
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.logs = []
        self.write("state.json", {"ok": True})
        self.write("token.json", {
            "ok": True,
            "data": self.DATA,
            "ts": 2_000_000_000,
            "fetched_at_utc": "2033-05-18T03:33:20Z",
            "rollcall_id": "r1",
        })
        config = qr_api.load_config(api_env(self.temp.name))
        self.server = qr_api.make_server(
            config, ("127.0.0.1", 0), wall_clock=lambda: self.NOW,
            monotonic=time.monotonic, log_sink=self.logs.append)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        raw = response.read()
        result = (response.status, {k.lower(): v for k, v in response.getheaders()}, raw)
        conn.close()
        return result

    def json_request(self, method, path, headers=None, body=None):
        status, headers_out, raw = self.request(method, path, headers, body)
        payload = json.loads(raw.decode("utf-8")) if raw else None
        return status, headers_out, payload

    def assert_security_headers(self, headers):
        for name, value in self.SECURITY.items():
            self.assertEqual(value, headers.get(name), name)
        self.assertNotIn("Python", headers.get("server", ""))
        self.assertNotIn("BaseHTTP", headers.get("server", ""))

    def test_health_is_fixed_allowlist_and_malicious_state_is_not_exposed(self):
        self.write("state.json", {
            "ok": False,
            "status": "attacker-controlled",
            "token": "LEAKED-TOKEN",
            "last_error": "UPSTREAM-SECRET-BODY",
            "permissions": "unsafe",
        })
        status, headers, payload = self.json_request("GET", "/health")
        self.assertEqual(503, status)
        self.assertEqual({"ok", "status", "token_fresh", "token_age_ms"}, set(payload))
        self.assertEqual("unhealthy", payload["status"])
        serialized = json.dumps(payload)
        self.assertNotIn("LEAKED-TOKEN", serialized)
        self.assertNotIn("UPSTREAM-SECRET-BODY", serialized)
        self.assert_security_headers(headers)

    def test_token_success_body_is_unchanged_and_read_is_strict(self):
        status, headers, payload = self.json_request(
            "GET", "/token", {"Authorization": "Bearer master-secret-value"})
        self.assertEqual(200, status)
        self.assertEqual({
            "ok": True,
            "data": self.DATA,
            "fetched_at_utc": "2033-05-18T03:33:20Z",
            "age_ms": 500,
        }, payload)
        self.assert_security_headers(headers)

        invalid_records = (
            {"ok": True, "data": self.DATA, "ts": 2_000_000_001},
            {"ok": True, "data": "1999999999" + "b" * 32, "ts": 1_999_999_999},
            {"ok": True, "data": "2000000002" + "c" * 32, "ts": 2_000_000_002},
        )
        for record in invalid_records:
            self.write("token.json", record)
            status, headers, payload = self.json_request(
                "GET", "/token", {"Authorization": "Bearer master-secret-value"})
            with self.subTest(record=record):
                self.assertEqual(503, status)
                self.assertNotIn("data", payload)
                self.assert_security_headers(headers)

    def test_managed_key_still_authorizes_token_but_not_restart(self):
        managed = "managed-key-secret"
        self.write("apikeys.json", {"keys": [{
            "id": "k_1",
            "hash": hashlib.sha256(managed.encode()).hexdigest(),
            "expires_epoch": int(self.NOW) + 60,
            "revoked": False,
        }]})
        status, unused, payload = self.json_request(
            "GET", "/token", {"Authorization": "Bearer " + managed})
        self.assertEqual(200, status)
        self.assertTrue(payload["ok"])
        status, headers, payload = self.json_request(
            "POST", "/restart", {"Authorization": "Bearer " + managed})
        self.assertEqual(401, status)
        self.assertEqual('Bearer realm="qr-api"', headers["www-authenticate"])
        self.assertEqual({"error": "unauthorized"}, payload)

    def test_head_options_and_restart_are_controlled(self):
        status, headers, raw = self.request("HEAD", "/token", {
            "Authorization": "Bearer master-secret-value"})
        self.assertEqual(200, status)
        self.assertEqual(b"", raw)
        self.assertGreater(int(headers["content-length"]), 0)
        self.assert_security_headers(headers)

        status, headers, raw = self.request("OPTIONS", "/restart")
        self.assertEqual(204, status)
        self.assertEqual(b"", raw)
        self.assertEqual("POST, OPTIONS", headers["allow"])
        self.assert_security_headers(headers)

        status, headers, payload = self.json_request(
            "POST", "/restart", {"Authorization": "Bearer master-secret-value"})
        self.assertEqual(200, status)
        self.assertEqual("2000000000500", payload["restart_nonce"])
        self.assertEqual({"cmd": "restart", "nonce": "2000000000500"},
                         json.loads((self.root / "control.json").read_text(encoding="utf-8")))
        self.assert_security_headers(headers)

    def test_401_404_405_501_and_503_are_json_with_security_headers(self):
        cases = []
        cases.append(self.json_request("GET", "/token"))
        cases.append(self.json_request("GET", "/missing/secret-value"))
        cases.append(self.json_request("POST", "/token"))
        cases.append(self.json_request("BREW", "/token"))
        self.write("state.json", {"ok": False})
        cases.append(self.json_request("GET", "/health"))
        self.assertEqual([401, 404, 405, 501, 503], [case[0] for case in cases])
        for status, headers, payload in cases:
            with self.subTest(status=status):
                self.assertIsInstance(payload, dict)
                self.assert_security_headers(headers)
        self.assertEqual('Bearer realm="qr-api"', cases[0][1]["www-authenticate"])
        self.assertEqual("GET, HEAD, OPTIONS", cases[2][1]["allow"])

    def test_429_has_retry_after_and_security_headers(self):
        clock = FakeClock()
        self.server.app.limiter.health_table = qr_api.TokenBucketTable(
            0.1, 1, 1, clock)
        self.assertEqual(200, self.request("GET", "/health")[0])
        status, headers, payload = self.json_request("GET", "/health")
        self.assertEqual(429, status)
        self.assertEqual("10", headers["retry-after"])
        self.assertEqual({"error": "rate_limited"}, payload)
        self.assert_security_headers(headers)

    def test_access_log_redacts_authorization_query_token_and_response_body(self):
        secret = "master-secret-value"
        query_secret = "QUERY-TOKEN-SECRET"
        status, unused, payload = self.json_request(
            "GET", "/token?debug=" + query_secret,
            {"Authorization": "Bearer " + secret})
        self.assertEqual(200, status)
        self.assertEqual(self.DATA, payload["data"])
        deadline = time.time() + 1
        while not self.logs and time.time() < deadline:
            time.sleep(0.01)
        serialized = json.dumps(self.logs)
        self.assertNotIn(secret, serialized)
        self.assertNotIn(query_secret, serialized)
        self.assertNotIn(self.DATA, serialized)
        self.assertNotIn("Authorization", serialized)
        access = self.logs[-1]
        self.assertEqual("http_access", access["event"])
        self.assertEqual("/token", access["path"])
        self.assertEqual(200, access["status"])


if __name__ == "__main__":
    unittest.main()
