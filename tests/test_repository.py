import functools
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


@functools.lru_cache(maxsize=1)
def tracked_files():
    output = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=str(ROOT))
    return tuple(pathlib.PurePosixPath(p.decode("utf-8"))
                 for p in output.split(b"\0") if p)


def env_names(name):
    names = set()
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            names.add(stripped.split("=", 1)[0])
    return names


class RepositoryHygieneTests(unittest.TestCase):
    def test_runtime_secrets_and_private_memory_are_not_tracked(self):
        paths = tracked_files()
        forbidden_names = {
            "secrets.env", "cookies.txt", "cookies-student.txt", "token.json",
            "state.json", "control.json", "control-ack.json", "rollcall.json", "apikeys.json",
        }
        for path in paths:
            text = path.as_posix()
            self.assertNotIn(path.name, forbidden_names, text)
            self.assertNotIn("Claude Memory/", text)
            self.assertNotIn("__pycache__/", text)
            self.assertNotEqual(".pyc", path.suffix, text)
            self.assertFalse(
                path.name.startswith("tokens-") and path.name.endswith(".jsonl.gz"), text)

    def test_public_tree_contains_no_retired_combined_environment_example(self):
        names = {path.as_posix() for path in tracked_files()}
        self.assertNotIn("secrets.env.example", names)
        self.assertIn("api.env.example", names)
        self.assertIn("keeper.env.example", names)

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

    def test_environment_examples_separate_service_secrets(self):
        api = env_names("api.env.example")
        keeper = env_names("keeper.env.example")
        common = env_names("common.env.example")
        self.assertIn("QR_API_KEY", api)
        self.assertIn("QR_SOURCE_REVISION", common)
        self.assertTrue({"QR_TEACHER_USER", "QR_TEACHER_PASS"}.issubset(keeper))
        self.assertTrue(api.isdisjoint({"QR_TEACHER_USER", "QR_TEACHER_PASS"}))
        self.assertTrue(keeper.isdisjoint({
            "QR_API_KEY", "QR_BIND", "QR_PORT", "QR_API_WORKERS",
            "QR_API_PENDING", "QR_GLOBAL_RATE", "QR_PRINCIPAL_RATE",
        }))
        # Shared non-secret env must not leak into secret files; secrets remain disjoint.
        self.assertTrue(common.isdisjoint({"QR_API_KEY", "QR_TEACHER_USER", "QR_TEACHER_PASS", "QR_BIND", "QR_PORT"}))
        self.assertFalse(any(name.startswith("QR_STUDENT_") for name in api | keeper | common))
        # Common shared values must also appear as documented fallback in service files.
        for shared in ("QR_WORKDIR", "QR_SOURCE_REVISION", "QR_STALE_MS", "QR_FUTURE_SKEW_MS"):
            self.assertIn(shared, api, shared)
            self.assertIn(shared, keeper, shared)
            self.assertIn(shared, common, shared)

    def test_ci_actions_are_pinned_to_exact_commits(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        uses = [line.strip().split("uses:", 1)[1].strip().split()[0]
                for line in text.splitlines() if "uses:" in line]
        self.assertTrue(uses)
        for reference in uses:
            with self.subTest(reference=reference):
                revision = reference.rsplit("@", 1)[-1]
                self.assertRegex(revision, r"^[0-9a-f]{40}$")

    def test_systemd_units_are_separate_explicit_and_hardened(self):
        # Enforce EnvironmentFile ordering: service-specific first, common last and optional;
        # common deterministically wins when present, without requiring common at boot.
        order_expect = {
            "qr-api.service": ("/etc/qr-harvest/api.env", "/etc/qr-harvest/common.env"),
            "qr-keeper.service": ("/etc/qr-harvest/keeper.env", "/etc/qr-harvest/common.env"),
        }
        expected_env = order_expect
        required = (
            "UMask=0077",
            "NoNewPrivileges=true",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "ReadWritePaths=/home/opc/qr-harvest",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectKernelLogs=true",
            "ProtectControlGroups=true",
            "RestrictNamespaces=true",
            "RestrictSUIDSGID=true",
            "RestrictRealtime=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "LockPersonality=true",
            "MemoryDenyWriteExecute=true",
            "SystemCallArchitectures=native",
            "RemoveIPC=true",
            "TasksMax=64",
            "MemoryMax=256M",
            "LimitNOFILE=1024",
            "TimeoutStopSec=30",
        )
        for name, environment_files in order_expect.items():
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(unit=name):
                self.assertIn("User=opc", text)
                self.assertIn("WorkingDirectory=/home/opc/qr-harvest", text)
                # Enforce exact precedence: service required first, common optional last.
                env_lines = [line.strip() for line in text.splitlines() if line.strip().startswith("EnvironmentFile")]
                self.assertEqual(2, len(env_lines), text)
                self.assertEqual("EnvironmentFile={}".format(environment_files[0]), env_lines[0])
                self.assertEqual("EnvironmentFile=-{}".format(environment_files[1]), env_lines[1])
                self.assertIn("ExecStart=/usr/bin/python3 /home/opc/qr-harvest/", text)
                read_only = next(
                    line for line in text.splitlines() if line.startswith("ReadOnlyPaths=")
                )
                for source in ("qr_api.py", "qr_keeper.py", "qr_keys.py", "qr_common.py"):
                    self.assertIn("/home/opc/qr-harvest/" + source, read_only)
                self.assertNotIn("/bin/sh", text)
                self.assertNotIn("secrets.env", text)
                for directive in required:
                    self.assertIn(directive, text)
                # OL8/systemd 239 does not support these newer directives; ensure we do not pretend they are active.
                for legacy in ("ProtectClock=true", "ProtectHostname=true", "ProtectProc=invisible", "ProcSubset=pid"):
                    self.assertNotIn(legacy, text)


    def test_forbidden_secrets_fail_closed(self):
        import sys
        sys.path.insert(0, str(ROOT))
        import qr_api
        import qr_keeper
        from qr_common import ConfigError
        with self.assertRaises(ConfigError):
            qr_api.load_config({"QR_SOURCE_REVISION": "a"*40, "QR_WORKDIR": "/tmp", "QR_BIND": "127.0.0.1", "QR_TEACHER_USER": "x", "QR_TEACHER_PASS": "y"})
        with self.assertRaises(ConfigError):
            qr_keeper.load_config({"QR_BASE": "https://www.tronclass.com.tw", "QR_COURSE_ID": "1", "QR_TEACHER_USER": "a", "QR_TEACHER_PASS": "b", "QR_SOURCE_REVISION": "a"*40, "QR_WORKDIR": "/tmp", "QR_PRESERVE_MODE": "off", "QR_API_KEY": "secret-value-0123456789abcdef-xxxx"})
        # Empty forbidden value is allowed (systemd may export empty).
        cfg = qr_api.load_config({"QR_SOURCE_REVISION": "a"*40, "QR_WORKDIR": "/tmp", "QR_BIND": "127.0.0.1", "QR_TEACHER_USER": "", "QR_TEACHER_PASS": ""})
        self.assertEqual("/tmp", cfg.workdir)

    def test_rollback_and_missing_common_is_safe(self):
        import sys
        sys.path.insert(0, str(ROOT))
        import qr_keeper
        old_env = {"QR_BASE": "https://www.tronclass.com.tw", "QR_COURSE_ID": "1", "QR_TEACHER_USER": "a", "QR_TEACHER_PASS": "b", "QR_SOURCE_REVISION": "a"*40, "QR_WORKDIR": "/tmp/old", "QR_PRESERVE_MODE": "off", "QR_STALE_MS": "9999"}
        cfg_old = qr_keeper.load_config(old_env)
        self.assertEqual(9999, cfg_old.stale_ms)
        merged = dict(old_env); merged.update({"QR_STALE_MS": "3000", "QR_WORKDIR": "/tmp/new"})
        cfg_new = qr_keeper.load_config(merged)
        self.assertEqual(3000, cfg_new.stale_ms)


if __name__ == "__main__":
    unittest.main()
