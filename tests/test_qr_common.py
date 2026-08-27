import json
import os
import pathlib
import tempfile
import threading
import unittest
from unittest.mock import patch

from qr_common import ConfigError, env_bool, env_choice, env_float, env_int, env_text
from qr_common import env_utc_date, validate_api_key_store, validate_token_record
from qr_common import write_json_atomic


class ConfigHelpersTests(unittest.TestCase):
    def test_required_and_placeholder_values_fail_closed(self):
        with self.assertRaises(ConfigError):
            env_text({}, "SECRET", required=True)
        with self.assertRaises(ConfigError):
            env_text({"SECRET": "<replace-with-secret>"}, "SECRET", required=True)
        self.assertEqual("real-value", env_text(
            {"SECRET": " real-value "}, "SECRET", required=True))

    def test_numeric_mode_and_date_validation(self):
        self.assertEqual(3, env_int({"N": "3"}, "N", 1, minimum=1))
        self.assertEqual(0.5, env_float(
            {"I": "0.5"}, "I", 1.0, minimum=0.0, minimum_exclusive=True))
        self.assertEqual("auto", env_choice(
            {"MODE": "AUTO"}, "MODE", "off", ("on", "off", "auto")))
        self.assertTrue(env_bool({"FLAG": "yes"}, "FLAG", False))
        self.assertFalse(env_bool({"FLAG": "off"}, "FLAG", True))
        with self.assertRaises(ConfigError):
            env_bool({"FLAG": "maybe"}, "FLAG", False)
        self.assertEqual("2026-08-31", env_utc_date(
            {"DATE": "2026-08-31"}, "DATE", required=True))
        for value in ("", "0", "-1", "nan", "inf"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                env_float({"I": value}, "I", 1.0,
                          minimum=0.0, minimum_exclusive=True)
        with self.assertRaises(ConfigError):
            env_choice({"MODE": "maybe"}, "MODE", "off", ("on", "off", "auto"))
        for value in ("2026-02-30", "2026/08/31", "31-08-2026"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                env_utc_date({"DATE": value}, "DATE", required=True)


class AtomicStoreTests(unittest.TestCase):
    def test_concurrent_writers_leave_one_complete_document_and_no_temp(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "state.json"
            errors = []

            def writer(value):
                try:
                    for _ in range(25):
                        write_json_atomic(path, {"value": value})
                except Exception as exc:  # pragma: no cover - assertion reports details
                    errors.append(exc)

            threads = [threading.Thread(target=writer, args=(value,)) for value in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual([], errors)
            self.assertIn(json.loads(path.read_text(encoding="utf-8"))["value"], range(4))
            self.assertEqual([], list(path.parent.glob(".state.json-*.tmp")))

    def test_durable_write_fsyncs_and_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "keys.json"
            with patch("qr_common.os.fsync", wraps=os.fsync) as fsync:
                write_json_atomic(path, {"keys": []}, durable=True)
            self.assertGreaterEqual(fsync.call_count, 1)

            link = pathlib.Path(temp) / "link.json"
            try:
                link.symlink_to(path)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(OSError):
                write_json_atomic(link, {"keys": []})
            self.assertEqual({"keys": []}, json.loads(path.read_text(encoding="utf-8")))


class ApiKeyStoreValidationTests(unittest.TestCase):
    @staticmethod
    def record(**changes):
        record = {
            "id": "k_1234abcd",
            "hash": "a" * 64,
            "label": "test",
            "created_utc": "2026-08-25T00:00:00Z",
            "expires_utc": "2026-08-26T00:00:00Z",
            "expires_epoch": 2_000_000_000,
            "revoked": False,
        }
        record.update(changes)
        return record

    def test_validates_entire_store_and_rejects_duplicates(self):
        valid = self.record()
        self.assertEqual([valid], validate_api_key_store({"keys": [valid]}))
        cases = (
            {"keys": [valid, dict(valid)]},
            {"keys": [self.record(hash="A" * 64)]},
            {"keys": [self.record(expires_epoch=True)]},
            {"keys": [self.record(label="bad\nlabel")]},
            {"keys": [{"id": "broken"}]},
        )
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_api_key_store(data)


class TokenValidationTests(unittest.TestCase):
    NOW_MS = 2_000_000_000_500
    DATA = "2000000000" + "a" * 32

    def record(self, **changes):
        record = {"ok": True, "data": self.DATA, "ts": 2_000_000_000}
        record.update(changes)
        return record

    def test_accepts_exact_stale_and_future_boundaries(self):
        self.assertTrue(validate_token_record(
            self.record(), self.NOW_MS, stale_ms=500, future_skew_ms=0).valid)
        future = {"ok": True, "data": "2000000001" + "b" * 32,
                  "ts": 2_000_000_001}
        self.assertTrue(validate_token_record(
            future, self.NOW_MS, stale_ms=500, future_skew_ms=500).valid)

    def test_rejects_just_outside_stale_and_future_boundaries(self):
        stale = validate_token_record(
            self.record(), self.NOW_MS + 1, stale_ms=500, future_skew_ms=500)
        self.assertEqual((False, "stale", 501),
                         (stale.valid, stale.error, stale.age_ms))
        future = {"ok": True, "data": "2000000001" + "b" * 32,
                  "ts": 2_000_000_001}
        result = validate_token_record(
            future, self.NOW_MS - 1, stale_ms=500, future_skew_ms=500)
        self.assertEqual((False, "future", -501),
                         (result.valid, result.error, result.age_ms))

    def test_rejects_shape_type_and_timestamp_mismatch(self):
        cases = (
            self.record(data="short"),
            self.record(data="2000000000" + "A" * 32),
            self.record(ts="2000000000"),
            self.record(ts=2_000_000_001),
            self.record(ok=1),
        )
        for record in cases:
            with self.subTest(record=record):
                self.assertFalse(validate_token_record(
                    record, self.NOW_MS, 3000, 1000).valid)


if __name__ == "__main__":
    unittest.main()
