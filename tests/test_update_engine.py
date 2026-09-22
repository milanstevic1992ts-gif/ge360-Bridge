import importlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class UpdateEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.wg = self.root / "wireguard"
        self.backups = self.root / "backups"
        self.updates = self.root / "updates"
        self.software = self.root / "opt"
        self.sbin = self.root / "sbin"
        self.systemd = self.root / "systemd"
        for path in (self.state, self.wg, self.backups, self.updates, self.software, self.sbin, self.systemd):
            path.mkdir(parents=True, exist_ok=True)

        os.environ["GE360_BRIDGE_STATE_DIR"] = str(self.state)
        os.environ["GE360_WG_CONF"] = str(self.wg / "wg0.conf")
        os.environ["GE360_BACKUP_DIR"] = str(self.backups)
        os.environ["GE360_UPDATE_STATE_DIR"] = str(self.updates)
        os.environ["GE360_SOFTWARE_ROOT"] = str(self.software)
        os.environ["GE360_LOCAL_SBIN"] = str(self.sbin)
        os.environ["GE360_SYSTEMD_DIR"] = str(self.systemd)

        import ge360_bridge.core as core
        self.core = importlib.reload(core)
        import ge360_bridge.backup as backup
        self.backup = importlib.reload(backup)
        import ge360_bridge.update_engine as update_engine
        self.up = importlib.reload(update_engine)

        self._write_config()
        self._write_installed_software()

    def tearDown(self):
        self.tmp.cleanup()
        for key in (
            "GE360_BRIDGE_STATE_DIR",
            "GE360_WG_CONF",
            "GE360_BACKUP_DIR",
            "GE360_UPDATE_STATE_DIR",
            "GE360_SOFTWARE_ROOT",
            "GE360_LOCAL_SBIN",
            "GE360_SYSTEMD_DIR",
        ):
            os.environ.pop(key, None)

    def _write_config(self):
        devices = [{
            "device_id": "dev_001",
            "name": "telefono",
            "device_type": "android",
            "owner": "",
            "vpn_ip": "10.88.0.2",
            "public_key": "public-key",
            "preshared_key": "psk",
            "token": "token",
            "created_at": "2026-09-22T00:00:00+00:00",
            "expires_at": None,
            "notes": "",
            "tags": [],
            "enabled": True,
        }]
        resources = [{
            "name": "rilievi",
            "bridge_port": 9888,
            "listen_port": 9888,
            "target_host": "127.0.0.1",
            "target_port": 9888,
            "allowed_devices": [],
            "denied_devices": [],
            "icon": "server",
            "description": "",
            "protocol": "http",
            "health_url": "/healthz",
            "timeout_seconds": 2.0,
            "systemd_unit": "",
            "self_heal_enabled": False,
            "enabled": True,
        }]
        groups = [{
            "name": "admin",
            "description": "",
            "device_ids": ["dev_001"],
            "allowed_services": ["rilievi"],
            "allowed_resources": ["rilievi"],
            "enabled": True,
        }]
        (self.state / "devices.json").write_text(json.dumps(devices), encoding="utf-8")
        (self.state / "resources.json").write_text(json.dumps(resources), encoding="utf-8")
        (self.state / "services.json").write_text(json.dumps(resources), encoding="utf-8")
        (self.state / "groups.json").write_text(json.dumps(groups), encoding="utf-8")
        (self.state / "bridge.env").write_text(
            "WG_INTERFACE=wg0\nWG_ADDRESS=10.88.0.1/24\nWG_PORT=51820\nPUBLIC_ENDPOINT=example.test:51820\nPAIRING_PORT=8790\n",
            encoding="utf-8",
        )
        for name, value in {
            "server.key": "server-private",
            "server.pub": "server-public",
            "dashboard.token": "dashboard-token",
            "enrollment.key": "enrollment-key",
            "pairing-tls.key": "tls-private",
            "pairing-tls.crt": "tls-cert",
        }.items():
            (self.state / name).write_text(value + "\n", encoding="utf-8")
        (self.wg / "wg0.conf").write_text(
            "[Interface]\nAddress = 10.88.0.1/24\nPrivateKey = server-private\n",
            encoding="utf-8",
        )

    def _write_installed_software(self):
        package = self.software / "ge360_bridge"
        package.mkdir(parents=True, exist_ok=True)
        for name in ("__init__.py", "cli.py", "core.py", "daemon.py", "dashboard.py", "pairing_server.py"):
            text = '__version__ = "0.18.0"\n' if name == "__init__.py" else f'OLD = "{name}"\n'
            (package / name).write_text(text, encoding="utf-8")
        wrapper = self.sbin / "ge360-bridge"
        wrapper.write_text("#!/usr/bin/env bash\necho old\n", encoding="utf-8")
        os.chmod(wrapper, 0o755)

    def _source_tree(self, version="9.0.0"):
        source = self.root / ("source-" + version.replace(".", "-"))
        package = source / "ge360_bridge"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
        for name in ("cli.py", "core.py", "daemon.py", "dashboard.py", "pairing_server.py", "backup.py", "update_engine.py"):
            (package / name).write_text(f'NEW = "{name}"\n', encoding="utf-8")
        (source / "ge360-bridge").write_text("#!/usr/bin/env bash\necho new\n", encoding="utf-8")
        return source

    def _build(self, version="9.0.0"):
        source = self._source_tree(version)
        output = self.root / f"update-{version}.tar.gz"
        result = self.up.build_update_package(source, output)
        return output, result

    def _runner_ok(self, args):
        return subprocess.CompletedProcess(["systemctl", *args], 0, "active\n", "")

    def test_build_and_verify_package(self):
        package, built = self._build()
        self.assertEqual(built["version"], "9.0.0")
        verified = self.up.verify_update(package)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["version"], "9.0.0")
        preflight = self.up.preflight_update(package)
        self.assertEqual(preflight["preflight"], "ok")

    def test_verify_rejects_not_newer_version(self):
        package, _ = self._build("0.1.0")
        with self.assertRaises(self.core.BridgeError):
            self.up.verify_update(package)

    def test_manifest_checksum_tamper_is_rejected(self):
        package, _ = self._build()
        tampered = self.root / "tampered.tar.gz"
        with tarfile.open(package, "r:gz") as src:
            entries = []
            for member in src.getmembers():
                stream = src.extractfile(member)
                entries.append((member.name, stream.read() if stream else b"", member.mode))
        entries = [
            (name, b"BROKEN" if name == "payload/ge360_bridge/core.py" else data, mode)
            for name, data, mode in entries
        ]
        with tarfile.open(tampered, "w:gz") as dst:
            for name, data, mode in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = mode
                dst.addfile(info, io.BytesIO(data))
        with self.assertRaises(self.core.BridgeError):
            self.up.verify_update(tampered)

    def test_unexpected_archive_path_is_rejected(self):
        evil = self.root / "evil.tar.gz"
        with tarfile.open(evil, "w:gz") as tf:
            data = b"x"
            info = tarfile.TarInfo("../escape")
            info.size = 1
            tf.addfile(info, io.BytesIO(data))
        with self.assertRaises(self.core.BridgeError):
            self.up.verify_update(evil, require_newer=False)

    def test_download_requires_https_and_checksum(self):
        with self.assertRaises(self.core.BridgeError):
            self.up.download_update("http://example.test/update.tar.gz", "0" * 64)

        payload = b"package-bytes"
        digest = self.up._sha256(payload)

        class Headers:
            def get(self, name, default=None):
                if name == "Content-Length":
                    return str(len(payload))
                return default

        class Response:
            headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "https://example.test/update.tar.gz"
            def read(self, n): return payload

        with patch.object(self.up, "urlopen", return_value=Response()):
            result = self.up.download_update("https://example.test/update.tar.gz", digest)
        self.assertEqual(result["sha256"], digest)
        self.assertTrue(Path(result["path"]).exists())

        with patch.object(self.up, "urlopen", return_value=Response()):
            with self.assertRaises(self.core.BridgeError):
                self.up.download_update("https://example.test/update.tar.gz", "f" * 64)

    def test_apply_success_creates_config_backup_and_software_rollback(self):
        package, _ = self._build()
        result = self.up.apply_update(
            package,
            runner=self._runner_ok,
            health_checker=lambda **kwargs: {"ok": True, "services": {}, "dashboard_health": True, "pairing_health": True},
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["rolled_back"])
        self.assertTrue((self.backups / result["config_backup"]).exists())
        self.assertTrue((self.updates / result["software_rollback"]).exists())
        installed = (self.software / "ge360_bridge/__init__.py").read_text(encoding="utf-8")
        self.assertIn("9.0.0", installed)
        self.assertIn("new", (self.sbin / "ge360-bridge").read_text(encoding="utf-8"))

    def test_failed_health_rolls_back_software_and_config(self):
        package, _ = self._build()
        original_core = (self.software / "ge360_bridge/core.py").read_bytes()
        calls = {"health": 0}

        def health(**kwargs):
            calls["health"] += 1
            return {"ok": calls["health"] >= 2}

        with self.assertRaises(self.core.BridgeError):
            self.up.apply_update(package, runner=self._runner_ok, health_checker=health)

        self.assertEqual((self.software / "ge360_bridge/core.py").read_bytes(), original_core)
        self.assertIn("0.18.0", (self.software / "ge360_bridge/__init__.py").read_text(encoding="utf-8"))
        status = self.up.update_status()
        self.assertFalse(status["last_update"]["ok"])
        self.assertTrue(status["last_update"]["rolled_back"])
        self.assertTrue(status["last_update"]["rollback_health"]["ok"])

    def test_failed_restart_rolls_back(self):
        package, _ = self._build()
        restart_count = {"n": 0}

        def runner(args):
            if args[:1] == ["restart"] and args[1:2] == ["ge360-bridge.service"]:
                restart_count["n"] += 1
                if restart_count["n"] == 1:
                    return subprocess.CompletedProcess(["systemctl", *args], 1, "", "boom")
            return subprocess.CompletedProcess(["systemctl", *args], 0, "active\n", "")

        with self.assertRaises(self.core.BridgeError):
            self.up.apply_update(
                package,
                runner=runner,
                health_checker=lambda **kwargs: {"ok": True},
            )
        self.assertIn("0.18.0", (self.software / "ge360_bridge/__init__.py").read_text(encoding="utf-8"))
        self.assertTrue(self.up.update_status()["last_update"]["rolled_back"])

    def test_only_three_rollback_snapshots_are_kept(self):
        source = self._source_tree()
        package_dir = source / "ge360_bridge"
        logical = ["ge360_bridge/__init__.py"]
        for i in range(5):
            self.up._create_software_rollback(logical, f"0.18.{i}")
        self.assertLessEqual(len(list(self.updates.glob("rollback-*.tar.gz"))), 3)


if __name__ == "__main__":
    unittest.main()
