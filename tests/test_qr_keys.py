import argparse
import pathlib
import tempfile
import unittest

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
        for value in ("0", "-1", "nan", "inf", "not-a-number"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                qr_keys.positive_days(value)

    def test_malformed_store_fails_closed_without_rewrite(self):
        path = pathlib.Path(qr_keys.KEYS_PATH)
        original = "not-json"
        path.write_text(original, encoding="utf-8")
        with self.assertRaises(RuntimeError):
            qr_keys._load()
        self.assertEqual(original, path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
