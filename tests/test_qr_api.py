import hashlib
import http.client
import json
import pathlib
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

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

    def test_rejected_client_does_not_drain_global_budget(self):
        clock = FakeClock()
        env = api_env("/tmp/qr-api-rate-order")
        env.update({
            "QR_GLOBAL_RATE": "0.001",
            "QR_GLOBAL_BURST": "2",
            "QR_PRINCIPAL_RATE": "0.001",
            "QR_PRINCIPAL_BURST": "1",
        })
        limiter = qr_api.RequestLimiter(qr_api.load_config(env), clock)
        self.assertTrue(limiter.check("/token", "ip:one")[0])
        self.assertFalse(limiter.check("/token", "ip:one")[0])
        self.assertTrue(
            limiter.check("/token", "ip:two")[0],
            "a denied client must not consume the remaining global token",
        )

    def test_health_buckets_are_per_client(self):
        clock = FakeClock()
        env = api_env("/tmp/qr-api-health-rate")
        env.update({"QR_HEALTH_RATE": "0.001", "QR_HEALTH_BURST": "1"})
        limiter = qr_api.RequestLimiter(qr_api.load_config(env), clock)
        self.assertTrue(limiter.check("/health", "ip:one")[0])
        self.assertFalse(limiter.check("/health", "ip:one")[0])
        self.assertTrue(limiter.check("/health", "ip:two")[0])


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

    def test_shutdown_cancels_pending_work_instead_of_draining_it(self):
        started = threading.Event()
        release = threading.Event()
        completed = []
        cancelled = []

        def blocking(value):
            started.set()
            release.wait(2)
            completed.append(value)

        executor = qr_api.BoundedExecutor(1, 2, name="shutdown-test")
        self.assertTrue(executor.submit(blocking, "running"))
        self.assertTrue(started.wait(1))
        self.assertTrue(executor.submit(blocking, "pending"))
        shutdown = threading.Thread(
            target=executor.shutdown,
            kwargs={"cancel_pending": cancelled.append},
        )
        shutdown.start()
        deadline = time.time() + 1
        while not cancelled and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(["pending"], cancelled)
        release.set()
        shutdown.join(2)
        self.assertFalse(shutdown.is_alive())
        self.assertEqual(["running"], completed)


def api_env(workdir):
    return {
        "QR_API_KEY": "master-secret-value-0123456789abcdef",
        "QR_SOURCE_REVISION": "a" * 40,
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


class ClientIdentityTests(unittest.TestCase):
    def test_cloudflare_ip_is_trusted_only_from_loopback(self):
        self.assertEqual(
            "203.0.113.9",
            qr_api.ApiApplication.client_ip("127.0.0.1", "203.0.113.9"),
        )
        self.assertEqual(
            "2001:db8::1",
            qr_api.ApiApplication.client_ip("::1", "2001:db8::1"),
        )
        self.assertEqual(
            "198.51.100.7",
            qr_api.ApiApplication.client_ip("198.51.100.7", "203.0.113.9"),
        )

    def test_invalid_or_ambiguous_header_falls_back_to_peer(self):
        for value in ("bad", "203.0.113.9, 198.51.100.1", " 203.0.113.9"):
            with self.subTest(value=value):
                self.assertEqual(
                    "127.0.0.1",
                    qr_api.ApiApplication.client_ip("127.0.0.1", value),
                )
        self.assertEqual("unknown", qr_api.ApiApplication.client_ip("not-an-ip", ""))


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
        env = api_env("/tmp/qr-api")
        env["QR_BIND"] = "0.0.0.0"
        cases.append(env)
        env = api_env("relative")
        cases.append(env)
        env = api_env("/tmp/qr-api")
        env["QR_API_KEY"] = "short"
        cases.append(env)
        env = api_env("/tmp/qr-api")
        env["QR_SOURCE_REVISION"] = "not-a-sha"
        cases.append(env)
        for env in cases:
            with self.subTest(env=env), self.assertRaises(ConfigError):
                qr_api.load_config(env)

    def test_master_key_may_be_omitted_for_managed_keys(self):
        env = api_env("/tmp/qr-api")
        env["QR_API_KEY"] = ""
        self.assertEqual("", qr_api.load_config(env).api_key)

    def test_workers_maximum_fits_tasks_max_with_margin(self):
        # qr-api.service TasksMax=64: 1 main thread + 60 executor workers
        # = 61 tasks, leaving 3 spare for transient spawn overlap.
        env = api_env("/tmp/qr-api")
        env["QR_API_WORKERS"] = "60"
        self.assertEqual(60, qr_api.load_config(env).workers)
        env = api_env("/tmp/qr-api")
        env["QR_API_WORKERS"] = "61"
        with self.assertRaises(ConfigError):
            qr_api.load_config(env)


class ApiServerTests(unittest.TestCase):
    NOW = 2_000_000_000.5
    DATA = "2000000000" + "a" * 32
    SECURITY = {
        "cache-control": "no-store, max-age=0",
        "link": '<https://github.com/hot-YUser/auto-Tronclass-VPS>; rel="source"',
        "x-source-revision": "a" * 40,
        "pragma": "no-cache",
        "expires": "0",
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

    def test_source_endpoint_is_fixed_public_metadata(self):
        status, headers, payload = self.json_request("GET", "/source")
        self.assertEqual(200, status)
        self.assertEqual({
            "repository": "https://github.com/hot-YUser/auto-Tronclass-VPS",
            "license": "AGPL-3.0",
            "revision": "a" * 40,
        }, payload)
        self.assert_security_headers(headers)
        status, headers, raw = self.request("HEAD", "/source")
        self.assertEqual(200, status)
        self.assertEqual(b"", raw)
        self.assert_security_headers(headers)

    def test_token_success_body_is_unchanged_and_read_is_strict(self):
        status, headers, payload = self.json_request(
            "GET", "/token", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
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
                "GET", "/token", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
            with self.subTest(record=record):
                self.assertEqual(503, status)
                self.assertNotIn("data", payload)
                self.assert_security_headers(headers)

    def test_managed_key_still_authorizes_token_but_not_restart(self):
        managed = "managed-key-secret"
        self.write("apikeys.json", {"keys": [{
            "id": "k_00000001",
            "hash": hashlib.sha256(managed.encode()).hexdigest(),
            "expires_epoch": int(self.NOW) + 60,
            "created_utc": "2033-05-18T03:32:20Z",
            "expires_utc": "2033-05-18T03:34:20Z",
            "label": "test",
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

    def test_corrupt_managed_store_fails_closed_as_a_whole(self):
        managed = "managed-key-secret"
        valid = {
            "id": "k_1234abcd",
            "hash": hashlib.sha256(managed.encode()).hexdigest(),
            "expires_epoch": int(self.NOW) + 60,
            "created_utc": "2033-05-18T03:32:20Z",
            "expires_utc": "2033-05-18T03:34:20Z",
            "label": "test",
            "revoked": False,
        }
        self.write("apikeys.json", {"keys": [valid, {"id": "broken"}]})
        status, unused, payload = self.json_request(
            "GET", "/token", {"Authorization": "Bearer " + managed})
        self.assertEqual(401, status)
        self.assertEqual({"error": "unauthorized"}, payload)

    def test_head_options_and_restart_are_controlled(self):
        status, headers, raw = self.request("HEAD", "/token", {
            "Authorization": "Bearer master-secret-value-0123456789abcdef"})
        self.assertEqual(200, status)
        self.assertEqual(b"", raw)
        self.assertGreater(int(headers["content-length"]), 0)
        self.assert_security_headers(headers)

        status, headers, raw = self.request("OPTIONS", "/restart")
        self.assertEqual(204, status)
        self.assertEqual(b"", raw)
        self.assertEqual("POST, OPTIONS", headers["allow"])
        self.assert_security_headers(headers)

        with patch.object(qr_api.secrets, "token_urlsafe", return_value="restart-nonce-1234"):
            status, headers, payload = self.json_request(
                "POST", "/restart", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
        self.assertEqual(202, status)
        self.assertEqual("accepted", payload["status"])
        self.assertEqual("restart-nonce-1234", payload["request_id"])
        self.assertEqual("restart-nonce-1234", payload["restart_nonce"])
        control = json.loads((self.root / "control.json").read_text(encoding="utf-8"))
        self.assertEqual(1, control["version"])
        self.assertEqual("restart", control["cmd"])
        self.assertEqual("restart-nonce-1234", control["request_id"])
        self.assertEqual(2_000_000_000_500, control["created_epoch_ms"])
        # Legacy compat: must remain consumable by old keeper.
        self.assertEqual("2000000000500", control["nonce"])
        self.assert_security_headers(headers)

    def test_restart_rejects_preserve_and_existing_pending_request(self):
        self.server.app.limiter.restart_table = qr_api.TokenBucketTable(
            1000, 1000, 1, FakeClock())
        self.write("state.json", {"ok": True, "preserve": True})
        status, unused, payload = self.json_request(
            "POST", "/restart", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
        self.assertEqual(409, status)
        self.assertEqual({"error": "preserve_active"}, payload)
        self.assertFalse((self.root / "control.json").exists())

        self.write("state.json", {"ok": True, "preserve": False})
        self.write("control.json", {
            "version": 1,
            "cmd": "restart",
            "request_id": "pending-request-123",
            "created_epoch_ms": 1,
        })
        status, unused, payload = self.json_request(
            "POST", "/restart", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
        self.assertEqual(409, status)
        self.assertEqual({"error": "restart_pending"}, payload)
        self.write("control-ack.json", {
            "version": 1,
            "request_id": "pending-request-123",
            "status": "completed",
        })
        with patch.object(qr_api.secrets, "token_urlsafe", return_value="next-request-12345"):
            status, unused, payload = self.json_request(
                "POST", "/restart", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
        self.assertEqual(202, status)
        self.assertEqual("next-request-12345", payload["request_id"])

    def test_unauthorized_and_options_do_not_drain_restart_admin_bucket(self):
        clock = FakeClock()
        self.server.app.limiter.restart_table = qr_api.TokenBucketTable(
            0.001, 1, 1, clock)
        self.assertEqual(204, self.request("OPTIONS", "/restart")[0])
        self.assertEqual(
            401,
            self.request(
                "POST", "/restart", {"Authorization": "Bearer wrong-key"})[0],
        )
        with patch.object(qr_api.secrets, "token_urlsafe", return_value="authorized-request-1"):
            self.assertEqual(
                202,
                self.request(
                    "POST", "/restart",
                    {"Authorization": "Bearer master-secret-value-0123456789abcdef"},
                )[0],
            )
        # Only the successful authenticated call consumed the admin bucket.
        self.write("control-ack.json", {
            "version": 1,
            "request_id": "authorized-request-1",
            "status": "completed",
        })
        self.assertEqual(
            429,
            self.request(
                "POST", "/restart",
                {"Authorization": "Bearer master-secret-value-0123456789abcdef"},
            )[0],
        )

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

    def test_fake_bearer_rotation_cannot_bypass_client_rate_limit(self):
        clock = FakeClock()
        self.server.app.limiter.principal_table = qr_api.TokenBucketTable(
            0.001, 1, 32, clock)
        first = self.json_request(
            "GET",
            "/token",
            {"Authorization": "Bearer fake-one", "CF-Connecting-IP": "203.0.113.9"},
        )
        second = self.json_request(
            "GET",
            "/token",
            {"Authorization": "Bearer fake-two", "CF-Connecting-IP": "203.0.113.9"},
        )
        other_client = self.json_request(
            "GET",
            "/token",
            {"Authorization": "Bearer fake-three", "CF-Connecting-IP": "203.0.113.10"},
        )
        self.assertEqual(401, first[0])
        self.assertEqual(429, second[0])
        self.assertEqual(401, other_client[0])

    def test_health_rate_limit_is_per_cloudflare_client(self):
        clock = FakeClock()
        self.server.app.limiter.health_table = qr_api.TokenBucketTable(
            0.001, 1, 32, clock)
        self.assertEqual(
            200,
            self.request("GET", "/health", {"CF-Connecting-IP": "203.0.113.20"})[0],
        )
        self.assertEqual(
            429,
            self.request("GET", "/health", {"CF-Connecting-IP": "203.0.113.20"})[0],
        )
        self.assertEqual(
            200,
            self.request("GET", "/health", {"CF-Connecting-IP": "203.0.113.21"})[0],
        )

    def test_unknown_routes_are_also_rate_limited_per_client(self):
        clock = FakeClock()
        self.server.app.limiter.principal_table = qr_api.TokenBucketTable(
            0.001, 1, 32, clock)
        headers = {"CF-Connecting-IP": "203.0.113.40"}
        self.assertEqual(404, self.request("GET", "/unknown-one", headers)[0])
        self.assertEqual(429, self.request("GET", "/unknown-two", headers)[0])
        self.assertEqual(
            404,
            self.request(
                "GET", "/unknown-three", {"CF-Connecting-IP": "203.0.113.41"}
            )[0],
        )

    def test_access_log_redacts_authorization_query_token_and_response_body(self):
        secret = "master-secret-value-0123456789abcdef"
        query_secret = "QUERY-TOKEN-SECRET"
        status, unused, payload = self.json_request(
            "GET", "/token?debug=" + query_secret,
            {"Authorization": "Bearer " + secret, "CF-Connecting-IP": "203.0.113.30"})
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
        self.assertEqual("203.0.113.30", access["remote"])
        self.assertEqual(200, access["status"])


    def test_keepalive_connection_close_header_forces_close(self):
        import socket
        s = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        crlf = chr(13) + chr(10)
        wire = crlf.join(["GET /health HTTP/1.1", "Host: 127.0.0.1", "Connection: keep-alive", "", ""])
        s.sendall(wire.encode())
        s.settimeout(2)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        self.assertIn(b"Connection: close", data)
        try:
            wire2 = crlf.join(["GET /health HTTP/1.1", "Host: 127.0.0.1", "", ""])
            s.sendall(wire2.encode())
            s.settimeout(1)
            extra = s.recv(4096)
        except OSError:
            extra = b""
        self.assertEqual(b"", extra)
        s.close()
        status, _headers, _payload = self.json_request("GET", "/health")
        self.assertEqual(200, status)

    def test_versioned_request_not_cleared_by_nonce_alias(self):
        self.write("control.json", {
            "version": 1,
            "cmd": "restart",
            "request_id": "versioned-request-123456",
            "created_epoch_ms": 1,
            "nonce": "old-ack-nonce-1234567890",
        })
        self.write("control-ack.json", {
            "version": 1,
            "request_id": "old-ack-nonce-1234567890",
            "status": "completed",
        })
        status, _headers, payload = self.json_request(
            "POST", "/restart", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
        self.assertEqual(409, status)
        self.assertEqual({"error": "restart_pending"}, payload)
        self.write("control-ack.json", {
            "version": 1,
            "request_id": "versioned-request-123456",
            "status": "completed",
        })
        import qr_api as api_mod, unittest.mock as mock
        with mock.patch.object(api_mod.secrets, "token_urlsafe", return_value="next-versioned-999999"):
            status, _headers, payload = self.json_request(
                "POST", "/restart", {"Authorization": "Bearer master-secret-value-0123456789abcdef"})
        self.assertEqual(202, status)
        self.assertEqual("next-versioned-999999", payload["request_id"])


class SyntheticMeasurementTests(unittest.TestCase):
    """Stdlib-only synthetic loopback measurement; reports timings, asserts only semantics.

    Reuses api_env()/make_server() with temporary synthetic fixtures. Elapsed
    times and RSS are printed for operators only; no test asserts any timing
    or memory threshold, and no real key or upstream is touched.
    """

    NOW = 2_000_000_000.5
    DATA = "2000000000" + "a" * 32

    def test_loopback_health_and_token_report_only(self):
        import tracemalloc

        try:
            import resource
        except ImportError:
            # POSIX-only; Windows CI reports tracemalloc + timings instead.
            resource = None

        temp = tempfile.TemporaryDirectory()
        try:
            root = pathlib.Path(temp.name)
            (root / "state.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
            (root / "token.json").write_text(json.dumps({
                "ok": True,
                "data": self.DATA,
                "ts": 2_000_000_000,
                "fetched_at_utc": "2033-05-18T03:33:20Z",
                "rollcall_id": "r1",
            }), encoding="utf-8")

            start = time.perf_counter()
            config = qr_api.load_config(api_env(temp.name))
            server = qr_api.make_server(
                config, ("127.0.0.1", 0), wall_clock=lambda: self.NOW,
                monotonic=time.monotonic, log_sink=lambda entry: None)
            import_ms = (time.perf_counter() - start) * 1000
            try:
                if resource is None:
                    rss_line = "max-rss=unavailable-on-this-platform"
                else:
                    try:
                        rss_kb = resource.getrusage(
                            resource.RUSAGE_SELF).ru_maxrss
                        rss_line = "max-rss={}KB".format(rss_kb)
                    except Exception:
                        rss_line = "max-rss=unavailable-on-this-platform"

                tracemalloc.start()
                thread = threading.Thread(
                    target=server.serve_forever, daemon=True)
                thread.start()
                port = server.server_address[1]
                begun_ms = (time.perf_counter() - start) * 1000

                def timed(method, path, headers=None):
                    conn = http.client.HTTPConnection(
                        "127.0.0.1", port, timeout=5)
                    begun = time.perf_counter()
                    conn.request(method, path, headers=headers or {})
                    response = conn.getresponse()
                    raw = response.read()
                    elapsed_ms = (time.perf_counter() - begun) * 1000
                    result = (response.status, raw)
                    conn.close()
                    return result, elapsed_ms

                (health_status, health_raw), health_ms = timed("GET", "/health")
                (token_status, token_raw), token_ms = timed(
                    "GET", "/token",
                    {"Authorization": "Bearer master-secret-value-0123456789abcdef"})

                current, peak = tracemalloc.get_traced_memory()
                print(
                    "synthetic-measurement import_ms={:.1f} startup_ms={:.1f} "
                    "health_ms={:.1f} token_ms={:.1f} {} "
                    "tracemalloc_current={}B peak={}B".format(
                        import_ms, begun_ms, health_ms, token_ms,
                        rss_line, current, peak),
                    flush=True)

                self.assertEqual(200, health_status)
                health = json.loads(health_raw.decode("utf-8"))
                self.assertEqual(
                    {"ok", "status", "token_fresh", "token_age_ms"},
                    set(health))
                self.assertEqual(200, token_status)
                token = json.loads(token_raw.decode("utf-8"))
                self.assertTrue(token["ok"])
                self.assertEqual(self.DATA, token["data"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
                tracemalloc.stop()
        finally:
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
