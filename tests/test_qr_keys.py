import argparse
import json
import pathlib
import tempfile
import threading
import unittest
from unittest.mock import patch

import qr_keys
from qr_common import ConfigError


class KeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.old_workdir = qr_keys.WORKDIR
        self.old_path = qr_keys.KEYS_PATH
        self.temp = tempfile.TemporaryDirectory()
        qr_keys.configure({"QR_WORKDIR": self.temp.name})

    def tearDown(self):
        qr_keys.WORKDIR = self.old_workdir
        qr_keys.KEYS_PATH = self.old_path
        self.temp.cleanup()

    def test_workdir_config_rejects_empty_and_placeholder_values(self):
        for value in ("", "<replace-with-workdir>"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                qr_keys.configure({"QR_WORKDIR": value})

    def test_ttl_must_be_positive_and_finite(self):
        self.assertEqual(0.5, qr_keys.positive_days("0.5"))
        for value in ("0", "-1", "nan", "inf", "not-a-number", "0.000000001", "3651"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                qr_keys.positive_days(value)

    def test_label_is_bounded_and_printable(self):
        self.assertEqual("device", qr_keys.safe_label("device"))
        for value in ("x" * 129, "bad\nlabel"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                qr_keys.safe_label(value)

    def test_concurrent_creates_preserve_every_key(self):
        args = argparse.Namespace(ttl_days=1.0, label="test")
        errors = []

        def create():
            try:
                qr_keys.cmd_create(args)
            except Exception as exc:  # pragma: no cover - assertion reports details
                errors.append(exc)

        with patch("builtins.print"):
            threads = [threading.Thread(target=create) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual([], errors)
        records = qr_keys._load()
        self.assertEqual(8, len(records))
        self.assertEqual(8, len({record["id"] for record in records}))
        self.assertEqual(8, len({record["hash"] for record in records}))
        stored = json.loads(pathlib.Path(qr_keys.KEYS_PATH).read_text(encoding="utf-8"))
        self.assertEqual(8, len(stored["keys"]))

    def test_invalid_record_schema_fails_closed(self):
        path = pathlib.Path(qr_keys.KEYS_PATH)
        path.write_text(json.dumps({"keys": [{"id": "broken"}]}), encoding="utf-8")
        original = path.read_bytes()
        with self.assertRaises(RuntimeError):
            qr_keys._load()
        self.assertEqual(original, path.read_bytes())

    def test_malformed_store_fails_closed_without_rewrite(self):
        path = pathlib.Path(qr_keys.KEYS_PATH)
        original = "not-json"
        path.write_text(original, encoding="utf-8")
        with self.assertRaises(RuntimeError):
            qr_keys._load()
        self.assertEqual(original, path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
