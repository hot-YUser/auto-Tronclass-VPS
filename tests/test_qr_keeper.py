import ast
import io
import json
import pathlib
import tempfile
import unittest
import urllib.error

import qr_keeper
from qr_common import ConfigError


ROOT = pathlib.Path(__file__).resolve().parents[1]


def valid_env(workdir="/tmp/qr-test"):
    return {
        "QR_BASE": "https://www.tronclass.com.tw",
        "QR_COURSE_ID": "55379",
        "QR_TEACHER_USER": "teacher@school.invalid",
        "QR_TEACHER_PASS": "valid-secret",
        "QR_WORKDIR": workdir,
        "QR_PRESERVE_MODE": "auto",
        "QR_PRESERVE_AFTER": "2026-08-31",
    }


class KeeperConfigTests(unittest.TestCase):
    def test_valid_config_loads(self):
        config = qr_keeper.load_config(valid_env())
        self.assertEqual("55379", config.course_id)
        self.assertEqual(0.5, config.poll_seconds)
        self.assertEqual(3000, config.stale_ms)

    def test_required_placeholders_modes_dates_and_intervals_fail_fast(self):
        cases = []
        for key in ("QR_COURSE_ID", "QR_TEACHER_USER", "QR_TEACHER_PASS"):
            env = valid_env()
            env[key] = ""
            cases.append(env)
        env = valid_env()
        env["QR_TEACHER_PASS"] = "<replace-with-password>"
        cases.append(env)
        env = valid_env()
        env["QR_PRESERVE_MODE"] = "sometimes"
        cases.append(env)
        env = valid_env()
        env["QR_PRESERVE_AFTER"] = "2026-02-30"
        cases.append(env)
        for key in ("QR_POLL_SECONDS", "QR_PASSIVE_CHECK_SECONDS",
                    "QR_STATE_WRITE_SECONDS", "QR_COOKIE_RESAVE_SECONDS",
                    "QR_SOCKET_TIMEOUT_SECONDS"):
            env = valid_env()
            env[key] = "0"
            cases.append(env)
        for env in cases:
            with self.subTest(env=env), self.assertRaises(ConfigError):
                qr_keeper.load_config(env)

    def test_auto_mode_requires_a_valid_date(self):
        env = valid_env()
        del env["QR_PRESERVE_AFTER"]
        with self.assertRaises(ConfigError):
            qr_keeper.load_config(env)


class KeeperBoundaryTests(unittest.TestCase):
    def test_source_has_no_learner_credentials_or_answer_mutation(self):
        source = (ROOT / "qr_keeper.py").read_text(encoding="utf-8")
        forbidden = (
            "QR_STUDENT_", "cookies-student", "answer_qr_rollcall",
            "qr-harvest-selftest", "login_probe", "SELFTEST_SECONDS",
            "LOGINPROBE_SECONDS",
        )
        for marker in forbidden:
            self.assertNotIn(marker, source)

    def test_passive_check_has_no_network_calls(self):
        tree = ast.parse((ROOT / "qr_keeper.py").read_text(encoding="utf-8"))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "passive_check")
        called = {node.func.id for node in ast.walk(function)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue({"_read_json", "validate_token_record"}.issubset(called))
        self.assertTrue(called.isdisjoint(
            {"_json_req", "login", "_opener", "create_rollcall", "stop_rollcall"}))

    def test_http_error_summary_does_not_read_upstream_body(self):
        body = io.BytesIO(b"upstream-secret-body")
        exc = urllib.error.HTTPError(
            "https://example.invalid", 500, "failure", {}, body)
        self.assertEqual("HTTP 500", qr_keeper._http_error_summary(exc))
        self.assertEqual(0, body.tell())
        exc.close()


class KeeperTokenTests(unittest.TestCase):
    def setUp(self):
        self.old_path = qr_keeper.TOKEN_PATH
        self.old_stale = qr_keeper.STALE_MS
        self.old_future = qr_keeper.FUTURE_SKEW_MS
        self.temp = tempfile.TemporaryDirectory()
        qr_keeper.TOKEN_PATH = str(pathlib.Path(self.temp.name) / "token.json")
        qr_keeper.STALE_MS = 500
        qr_keeper.FUTURE_SKEW_MS = 500

    def tearDown(self):
        qr_keeper.TOKEN_PATH = self.old_path
        qr_keeper.STALE_MS = self.old_stale
        qr_keeper.FUTURE_SKEW_MS = self.old_future
        self.temp.cleanup()

    def test_keeper_validates_before_atomic_write(self):
        data = "2000000000" + "a" * 32
        checked = qr_keeper._write_token(
            data, "r1", now_ms=2_000_000_000_500)
        self.assertEqual(500, checked.age_ms)
        self.assertEqual(2_000_000_000, checked.timestamp)
        record = json.loads(pathlib.Path(qr_keeper.TOKEN_PATH).read_text(encoding="utf-8"))
        self.assertEqual(data, record["data"])
        self.assertEqual(2_000_000_000, record["ts"])

    def test_keeper_rejects_stale_future_and_bad_shape(self):
        cases = (
            ("2000000000" + "a" * 32, 2_000_000_000_501),
            ("2000000001" + "b" * 32, 2_000_000_000_499),
            ("2000000000" + "C" * 32, 2_000_000_000_500),
            ("not-a-token", 2_000_000_000_500),
        )
        for data, now_ms in cases:
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                qr_keeper._write_token(data, "r1", now_ms=now_ms)
        self.assertFalse(pathlib.Path(qr_keeper.TOKEN_PATH).exists())

    def test_corpus_close_flushes_and_closes(self):
        class Sink:
            def __init__(self):
                self.flushed = False
                self.closed = False

            def flush(self):
                self.flushed = True

            def close(self):
                self.closed = True

        corpus = qr_keeper.Corpus()
        sink = Sink()
        corpus.f = sink
        corpus.close()
        self.assertTrue(sink.flushed)
        self.assertTrue(sink.closed)
        self.assertIsNone(corpus.f)


if __name__ == "__main__":
    unittest.main()
