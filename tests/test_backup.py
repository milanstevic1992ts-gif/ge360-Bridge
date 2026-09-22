import importlib
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.wireguard = self.root / "wireguard"
        self.backups = self.root / "backups"
        self.state.mkdir()
        self.wireguard.mkdir()

        os.environ["GE360_BRIDGE_STATE_DIR"] = str(self.state)
        os.environ["GE360_WG_CONF"] = str(self.wireguard / "wg0.conf")
        os.environ["GE360_BACKUP_DIR"] = str(self.backups)

        import ge360_bridge.core as core
        self.core = importlib.reload(core)
        import ge360_bridge.backup as backup
        self.backup = importlib.reload(backup)

        self._write_valid_config()

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)
        os.environ.pop("GE360_WG_CONF", None)
        os.environ.pop("GE360_BACKUP_DIR", None)

    def _write_valid_config(self):
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
            "systemd_unit": "ge360-rilievi.service",
            "self_heal_enabled": True,
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
        (self.state / "server.key").write_text("server-private-key\n", encoding="utf-8")
        (self.state / "server.pub").write_text("server-public-key\n", encoding="utf-8")
        (self.state / "dashboard.token").write_text("dashboard-token-0123456789\n", encoding="utf-8")
        (self.state / "enrollment.key").write_text("enrollment-secret\n", encoding="utf-8")
        (self.state / "pairing-tls.key").write_text("tls-private-key\n", encoding="utf-8")
        (self.state / "pairing-tls.crt").write_text("tls-certificate\n", encoding="utf-8")
        (self.wireguard / "wg0.conf").write_text(
            "[Interface]\nAddress = 10.88.0.1/24\nListenPort = 51820\nPrivateKey = server-private-key\n",
            encoding="utf-8",
        )
        (self.state / "audit.db").write_bytes(b"audit-not-backup")
        (self.state / "metrics.db").write_bytes(b"metrics-not-backup")
        (self.state / "enrollments.json").write_text("[]\n", encoding="utf-8")
        (self.state / "self_heal_state.json").write_text('{"rilievi":[1,2]}\n', encoding="utf-8")

    def test_create_backup_is_private_and_excludes_runtime_files(self):
        result = self.backup.create_backup(now=datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc))
        self.assertTrue(result["created"])
        path = self.backups / result["backup"]
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.backups.stat().st_mode), 0o700)

        with tarfile.open(path, "r:gz") as tf:
            names = set(tf.getnames())
        self.assertIn("state/devices.json", names)
        self.assertIn("state/server.key", names)
        self.assertIn("wireguard/wg0.conf", names)
        self.assertNotIn("state/audit.db", names)
        self.assertNotIn("state/metrics.db", names)
        self.assertNotIn("state/enrollments.json", names)
        self.assertNotIn("state/self_heal_state.json", names)

        verified = self.backup.verify_backup(result["backup"])
        self.assertTrue(verified["valid"])
        self.assertFalse(verified["contains_client_private_keys"])
        self.assertTrue(verified["contains_server_secrets"])

    def test_optional_relay_token_is_backed_up_and_restored(self):
        relay_token = self.state / "relay.token"
        relay_token.write_text("relay-admin-secret\n", encoding="utf-8")
        created = self.backup.create_backup(
            now=datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
        )
        with tarfile.open(self.backups / created["backup"], "r:gz") as tf:
            names = set(tf.getnames())
        self.assertIn("state/relay.token", names)

        relay_token.write_text("changed\n", encoding="utf-8")
        restored = self.backup.restore_backup(
            created["backup"],
            apply=True,
            create_safety_backup=False,
        )
        self.assertIn(str(relay_token), restored["restored"])
        self.assertEqual(relay_token.read_text(encoding="utf-8"), "relay-admin-secret\n")

    def test_client_private_key_field_blocks_backup(self):
        devices = json.loads((self.state / "devices.json").read_text(encoding="utf-8"))
        devices[0]["private_key"] = "must-never-leave-client"
        (self.state / "devices.json").write_text(json.dumps(devices), encoding="utf-8")
        with self.assertRaises(self.core.BridgeError):
            self.backup.create_backup(now=datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc))

    def test_retention_keeps_exactly_ten_newest(self):
        start = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
        for index in range(12):
            self.backup.create_backup(
                keep=10,
                now=start + timedelta(days=index),
                reason="manual",
            )
        names = sorted(p.name for p in self.backups.glob("ge360-config-*.tar.gz"))
        self.assertEqual(len(names), 10)
        self.assertFalse(any("20260901" in name for name in names))
        self.assertFalse(any("20260902" in name for name in names))
        self.assertTrue(any("20260912" in name for name in names))

    def test_scheduled_backup_is_at_most_one_per_utc_day(self):
        first = self.backup.create_backup(
            scheduled=True,
            now=datetime(2026, 9, 22, 3, 0, tzinfo=timezone.utc),
        )
        second = self.backup.create_backup(
            scheduled=True,
            now=datetime(2026, 9, 22, 18, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(first["created"])
        self.assertTrue(second["skipped"])
        self.assertEqual(first["backup"], second["backup"])
        self.assertEqual(len(list(self.backups.glob("*-daily.tar.gz"))), 1)

    def test_checksum_tamper_is_rejected(self):
        created = self.backup.create_backup(now=datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc))
        original = self.backups / created["backup"]
        tampered = self.backups / "tampered.tar.gz"

        with tarfile.open(original, "r:gz") as src:
            members = {}
            for member in src.getmembers():
                stream = src.extractfile(member)
                members[member.name] = stream.read() if stream else b""
        members["state/devices.json"] = b"[]"

        with tarfile.open(tampered, "w:gz") as dst:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                dst.addfile(info, io.BytesIO(data))

        with self.assertRaises(self.core.BridgeError):
            self.backup.verify_backup("tampered.tar.gz")

    def test_archive_with_unexpected_path_is_rejected(self):
        path = self.backups
        path.mkdir(parents=True, exist_ok=True)
        evil = path / "evil.tar.gz"
        with tarfile.open(evil, "w:gz") as tf:
            data = b"x"
            info = tarfile.TarInfo("../escape")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        with self.assertRaises(self.core.BridgeError):
            self.backup.verify_backup("evil.tar.gz")

    def test_restore_dry_run_does_not_change_config(self):
        created = self.backup.create_backup(now=datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc))
        before = (self.state / "devices.json").read_bytes()
        devices = json.loads(before.decode("utf-8"))
        devices[0]["name"] = "mutato"
        (self.state / "devices.json").write_text(json.dumps(devices), encoding="utf-8")

        plan = self.backup.restore_backup(created["backup"], apply=False)
        self.assertTrue(plan["verified"])
        self.assertFalse(plan["apply"])
        current = json.loads((self.state / "devices.json").read_text(encoding="utf-8"))
        self.assertEqual(current[0]["name"], "mutato")

    def test_restore_apply_restores_and_creates_safety_backup(self):
        created = self.backup.create_backup(now=datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc))
        devices = json.loads((self.state / "devices.json").read_text(encoding="utf-8"))
        devices[0]["name"] = "mutato"
        (self.state / "devices.json").write_text(json.dumps(devices), encoding="utf-8")

        result = self.backup.restore_backup(created["backup"], apply=True)
        restored = json.loads((self.state / "devices.json").read_text(encoding="utf-8"))
        self.assertEqual(restored[0]["name"], "telefono")
        self.assertTrue(result["safety_backup"])
        self.assertTrue((self.backups / result["safety_backup"]).exists())

    def test_restore_rejects_non_basename_identifier(self):
        with self.assertRaises(self.core.BridgeError):
            self.backup.verify_backup("../backup.tar.gz")


if __name__ == "__main__":
    unittest.main()
