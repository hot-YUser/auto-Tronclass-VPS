import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def tracked_files():
    output = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=str(ROOT))
    return [pathlib.PurePosixPath(p.decode("utf-8"))
            for p in output.split(b"\0") if p]


class RepositoryHygieneTests(unittest.TestCase):
    def test_runtime_secrets_and_private_memory_are_not_tracked(self):
        paths = tracked_files()
        forbidden_names = {
            "secrets.env", "cookies.txt", "cookies-student.txt", "token.json",
            "state.json", "control.json", "rollcall.json", "apikeys.json",
        }
        for path in paths:
            text = path.as_posix()
            self.assertNotIn(path.name, forbidden_names, text)
            self.assertNotIn("Claude Memory/", text)
            self.assertNotIn("__pycache__/", text)
            self.assertNotEqual(".pyc", path.suffix, text)
            self.assertFalse(path.name.startswith("tokens-") and path.name.endswith(".jsonl.gz"), text)

    def test_tracked_text_uses_lf(self):
        for relative in tracked_files():
            path = ROOT.joinpath(*relative.parts)
            data = path.read_bytes()
            if b"\0" in data:
                continue
            with self.subTest(path=relative.as_posix()):
                self.assertNotIn(b"\r\n", data)

    def test_license_is_unmodified_agplv3(self):
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", license_text)
        self.assertIn("Version 3, 19 November 2007", license_text)

    def test_systemd_units_use_explicit_startup_paths(self):
        for name in ("qr-api.service", "qr-keeper.service"):
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(unit=name):
                self.assertIn("WorkingDirectory=/", text)
                self.assertIn("EnvironmentFile=/", text)
                self.assertIn("ExecStart=/usr/bin/python3 /", text)
                self.assertNotIn("/bin/sh", text)


if __name__ == "__main__":
    unittest.main()
