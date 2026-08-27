import ast
import gzip
import io
import json
import pathlib
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

import qr_keeper
from qr_common import ConfigError


ROOT = pathlib.Path(__file__).resolve().parents[1]


def valid_env(workdir="/tmp/qr-test"):
    return {
        "QR_BASE": "https://www.tronclass.com.tw",
        "QR_COURSE_ID": "55379",
        "QR_TEACHER_USER": "teacher@school.invalid",
        "QR_TEACHER_PASS": "valid-secret",
        "QR_SOURCE_REVISION": "a" * 40,
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
        self.assertFalse(config.corpus_enabled)
        self.assertEqual(30, config.corpus_max_days)

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
        env = valid_env()
        env["QR_BASE"] = "https://example.invalid/path?secret=x"
        cases.append(env)
        env = valid_env("relative")
        cases.append(env)
        for key in ("QR_POLL_SECONDS", "QR_PASSIVE_CHECK_SECONDS",
                    "QR_STATE_WRITE_SECONDS", "QR_COOKIE_RESAVE_SECONDS",
                    "QR_SOCKET_TIMEOUT_SECONDS", "QR_CORPUS_MAX_BYTES",
                    "QR_CORPUS_MAX_DAYS", "QR_CORPUS_FLUSH_RECORDS"):
            env = valid_env()
            env[key] = "0"
            cases.append(env)
        env = valid_env()
        env["QR_CORPUS_ENABLED"] = "maybe"
        cases.append(env)
        env = valid_env()
        env["QR_SOURCE_REVISION"] = "not-a-sha"
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
    def test_http_body_is_bounded_and_auth_errors_are_typed(self):
        with self.assertRaises(RuntimeError):
            qr_keeper._read_http_text(io.BytesIO(b"x" * 11), limit=10)

        class UnauthorizedOp:
            def open(self, request):
                raise urllib.error.HTTPError(
                    str(request), 401, "unauthorized", {}, io.BytesIO(b"secret"))

        with self.assertRaises(qr_keeper.AuthenticationLost):
            qr_keeper._json_req(UnauthorizedOp(), "https://example.invalid/api")

    def test_create_requires_start_success_and_cleans_failed_source(self):
        with (
            patch.object(qr_keeper, "_duration_ladder", return_value=(10,)),
            patch.object(qr_keeper, "_json_req", side_effect=[
                (201, {"id": "new-rid"}),
                (400, {"error": "bad duration"}),
                (204, None),
            ]) as request,
        ):
            with self.assertRaises(RuntimeError):
                qr_keeper.create_rollcall(object())
        self.assertEqual(3, request.call_count)
        self.assertIn("stop_qr_rollcall", request.call_args_list[-1].args[1])


class KeeperControlTests(unittest.TestCase):
    def setUp(self):
        self.old_control = qr_keeper.CONTROL_PATH
        self.old_ack = qr_keeper.CONTROL_ACK_PATH
        self.old_rid = qr_keeper.RID_PATH
        self.temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temp.name)
        qr_keeper.CONTROL_PATH = str(root / "control.json")
        qr_keeper.CONTROL_ACK_PATH = str(root / "control-ack.json")
        qr_keeper.RID_PATH = str(root / "rollcall.json")
        qr_keeper.STOP_EVENT.clear()

    def tearDown(self):
        qr_keeper.CONTROL_PATH = self.old_control
        qr_keeper.CONTROL_ACK_PATH = self.old_ack
        qr_keeper.RID_PATH = self.old_rid
        qr_keeper.STOP_EVENT.clear()
        self.temp.cleanup()

    @staticmethod
    def request(request_id="request-id-123456"):
        return {
            "version": 1,
            "cmd": "restart",
            "request_id": request_id,
            "created_epoch_ms": 1,
        }

    def test_control_request_is_versioned_and_terminal_ack_stops_replay(self):
        pathlib.Path(qr_keeper.CONTROL_PATH).write_text(
            json.dumps(self.request()), encoding="utf-8")
        self.assertEqual(self.request(), qr_keeper._restart_request_pending())
        qr_keeper._write_control_ack(self.request(), "accepted", rollcall_id="old")
        self.assertEqual(self.request(), qr_keeper._restart_request_pending())
        qr_keeper._write_control_ack(self.request(), "completed", rollcall_id="new")
        self.assertIsNone(qr_keeper._restart_request_pending())

        pathlib.Path(qr_keeper.CONTROL_PATH).write_text(
            json.dumps({"cmd": "restart", "nonce": "legacy"}), encoding="utf-8")
        self.assertIsNone(qr_keeper._control_request())

    def test_restart_waits_for_close_and_acks_only_after_token_boundary(self):
        request = self.request()
        with (
            patch.object(qr_keeper, "_rollcall_in_progress", return_value=True),
            patch.object(qr_keeper, "stop_rollcall", return_value=True),
            patch.object(qr_keeper, "_wait_rollcall_closed", return_value=True),
            patch.object(qr_keeper, "create_rollcall", return_value="new-rid"),
        ):
            rid, pending = qr_keeper._restart_rollcall(object(), "old-rid", request)
        self.assertEqual("new-rid", rid)
        self.assertEqual(request, pending["request"])
        ack = json.loads(pathlib.Path(qr_keeper.CONTROL_ACK_PATH).read_text(encoding="utf-8"))
        self.assertEqual("accepted", ack["status"])
        self.assertNotEqual("completed", ack["status"])
        saved = json.loads(pathlib.Path(qr_keeper.RID_PATH).read_text(encoding="utf-8"))
        self.assertEqual("new-rid", saved["rollcall_id"])

    def test_restart_failure_is_terminal_and_preserves_old_rid(self):
        request = self.request()
        with (
            patch.object(qr_keeper, "_rollcall_in_progress", return_value=True),
            patch.object(qr_keeper, "stop_rollcall", return_value=False),
        ):
            rid, pending = qr_keeper._restart_rollcall(object(), "old-rid", request)
        self.assertEqual("old-rid", rid)
        self.assertIsNone(pending)
        ack = json.loads(pathlib.Path(qr_keeper.CONTROL_ACK_PATH).read_text(encoding="utf-8"))
        self.assertEqual("failed", ack["status"])
        self.assertEqual("stop_failed", ack["error"])


    def test_supervisor_stops_process_on_worker_crash(self):
        qr_keeper.STOP_EVENT.clear()

        def crash():
            raise RuntimeError("sensitive-detail")

        with patch("builtins.print") as printed:
            qr_keeper._run_supervised("test_worker", crash)
        self.assertTrue(qr_keeper.STOP_EVENT.is_set())
        rendered = " ".join(str(arg) for call in printed.call_args_list for arg in call.args)
        self.assertNotIn("sensitive-detail", rendered)
        self.assertIn("RuntimeError", rendered)
        qr_keeper.STOP_EVENT.clear()


class CorpusRetentionTests(unittest.TestCase):
    def setUp(self):
        self.saved = {
            "WORKDIR": qr_keeper.WORKDIR,
            "CORPUS_ENABLED": qr_keeper.CORPUS_ENABLED,
            "CORPUS_MAX_BYTES": qr_keeper.CORPUS_MAX_BYTES,
            "CORPUS_MAX_DAYS": qr_keeper.CORPUS_MAX_DAYS,
            "CORPUS_MIN_FREE_BYTES": qr_keeper.CORPUS_MIN_FREE_BYTES,
            "CORPUS_FLUSH_RECORDS": qr_keeper.CORPUS_FLUSH_RECORDS,
        }
        self.temp = tempfile.TemporaryDirectory()
        qr_keeper.WORKDIR = self.temp.name
        qr_keeper.CORPUS_MAX_BYTES = 1024 * 1024
        qr_keeper.CORPUS_MAX_DAYS = 30
        qr_keeper.CORPUS_MIN_FREE_BYTES = 0
        qr_keeper.CORPUS_FLUSH_RECORDS = 1

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(qr_keeper, name, value)
        self.temp.cleanup()

    def test_corpus_is_default_off_and_writes_only_after_opt_in(self):
        qr_keeper.CORPUS_ENABLED = False
        disabled = qr_keeper.Corpus()
        disabled.write('{"data":"secret"}')
        self.assertEqual([], list(pathlib.Path(self.temp.name).glob("tokens-*.gz")))

        qr_keeper.CORPUS_ENABLED = True
        enabled = qr_keeper.Corpus()
        enabled.write('{"data":"test"}')
        enabled.close()
        paths = list(pathlib.Path(self.temp.name).glob("tokens-*.jsonl.gz"))
        self.assertEqual(1, len(paths))
        with gzip.open(paths[0], "rt", encoding="utf-8") as handle:
            self.assertEqual('{"data":"test"}', handle.read().strip())

    def test_prune_enforces_age_and_total_size_including_last_file(self):
        qr_keeper.CORPUS_ENABLED = True
        root = pathlib.Path(self.temp.name)
        current = time.strftime("%Y%m%d", time.gmtime())
        previous = time.strftime("%Y%m%d", time.gmtime(time.time() - 86400))
        old = root / "tokens-20000101.jsonl.gz"
        prior = root / "tokens-{}.jsonl.gz".format(previous)
        today = root / "tokens-{}.jsonl.gz".format(current)
        old.write_bytes(b"o" * 5)
        prior.write_bytes(b"p" * 8)
        today.write_bytes(b"t" * 8)

        qr_keeper.CORPUS_MAX_DAYS = 2
        qr_keeper.CORPUS_MAX_BYTES = 10
        total = qr_keeper.Corpus()._prune()
        self.assertFalse(old.exists())
        self.assertFalse(prior.exists())
        self.assertTrue(today.exists())
        self.assertEqual(8, total)

        qr_keeper.CORPUS_MAX_BYTES = 4
        total = qr_keeper.Corpus()._prune()
        self.assertFalse(today.exists(), "a sole oversized file must not be exempt")
        self.assertEqual(0, total)


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

    def test_corpus_disable_is_sticky(self):
        corpus = qr_keeper.Corpus()
        corpus.disable()
        self.assertTrue(corpus.disabled)
        with patch.object(corpus, "_open_day") as open_day:
            corpus.write("ignored")
        open_day.assert_not_called()


if __name__ == "__main__":
    unittest.main()
