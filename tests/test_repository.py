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
        self.assertIn("QR_API_KEY", api)
        self.assertIn("QR_SOURCE_REVISION", api)
        self.assertIn("QR_SOURCE_REVISION", keeper)
        self.assertTrue({"QR_TEACHER_USER", "QR_TEACHER_PASS"}.issubset(keeper))
        self.assertTrue(api.isdisjoint({"QR_TEACHER_USER", "QR_TEACHER_PASS"}))
        self.assertTrue(keeper.isdisjoint({
            "QR_API_KEY", "QR_BIND", "QR_PORT", "QR_API_WORKERS",
            "QR_API_PENDING", "QR_GLOBAL_RATE", "QR_PRINCIPAL_RATE",
        }))
        self.assertFalse(any(name.startswith("QR_STUDENT_") for name in api | keeper))

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
        expected_env = {
            "qr-api.service": "/etc/qr-harvest/api.env",
            "qr-keeper.service": "/etc/qr-harvest/keeper.env",
        }
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
            "ProtectClock=true",
            "ProtectHostname=true",
            "ProtectProc=invisible",
            "ProcSubset=pid",
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
        for name, environment_file in expected_env.items():
            text = (ROOT / name).read_text(encoding="utf-8")
            with self.subTest(unit=name):
                self.assertIn("User=opc", text)
                self.assertIn("WorkingDirectory=/home/opc/qr-harvest", text)
                self.assertIn("EnvironmentFile={}".format(environment_file), text)
                self.assertIn("ExecStart=/usr/bin/python3 /home/opc/qr-harvest/", text)
                read_only = next(
                    line for line in text.splitlines() if line.startswith("ReadOnlyPaths=")
                )
                for source in ("qr_api.py", "qr_keeper.py", "qr_keys.py", "qr_common.py"):
                    self.assertIn("/home/opc/qr-harvest/" + source, read_only)
                self.assertNotIn("/bin/sh", text)
                for directive in required:
                    self.assertIn(directive, text)


if __name__ == "__main__":
    unittest.main()
