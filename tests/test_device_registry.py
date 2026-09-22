import importlib
import os
import tempfile
import unittest
from datetime import date


class DeviceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name
        import ge360_bridge.core as core
        self.core = importlib.reload(core)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)

    def legacy_device(self):
        return {
            "name": "telefono",
            "vpn_ip": "10.88.0.2",
            "public_key": "peer-public-key",
            "preshared_key": "psk",
            "token": "token",
            "enabled": True,
        }

    def test_legacy_migration_preserves_peer_and_adds_registry_fields(self):
        self.core._atomic_write(self.core.DEVICES_FILE, [self.legacy_device()])
        changed = self.core.upgrade_device_registry()
        self.assertEqual(changed, 1)
        device = self.core.list_devices()[0]
        self.assertTrue(device["device_id"].startswith("dev_"))
        self.assertEqual(device["name"], "telefono")
        self.assertEqual(device["vpn_ip"], "10.88.0.2")
        self.assertEqual(device["public_key"], "peer-public-key")
        self.assertEqual(device["device_type"], "unknown")
        self.assertEqual(device["owner"], "")
        self.assertIsNone(device["expires_at"])
        self.assertEqual(device["tags"], [])
        stable_id = device["device_id"]
        self.core.upgrade_device_registry()
        self.assertEqual(self.core.list_devices()[0]["device_id"], stable_id)

    def test_rename_updates_existing_service_acl(self):
        self.core.save_devices([self.legacy_device()])
        device = self.core.list_devices()[0]
        self.core.register_service("rilievi", 9888, "127.0.0.1", 9888, ["telefono"])
        self.core.rename_device(device["device_id"], "telefono-milan")
        self.assertEqual(self.core.list_devices()[0]["name"], "telefono-milan")
        self.assertEqual(self.core.list_services()[0]["allowed_devices"], ["telefono-milan"])

    def test_expired_device_is_removed_from_runtime_acl(self):
        d = self.legacy_device()
        d["expires_at"] = "2026-09-21"
        self.core.save_devices([d])
        service = self.core.register_service("rilievi", 9888, "127.0.0.1", 9888, ["telefono"])
        device = self.core.list_devices()[0]
        self.assertTrue(self.core.device_is_expired(device, date(2026, 9, 22)))
        self.assertEqual(
            self.core.allowed_ips_for_service(service.__dict__, self.core.list_devices()),
            set(),
        )

    def test_metadata_and_enable_disable(self):
        self.core.save_devices([self.legacy_device()])
        device = self.core.list_devices()[0]
        updated = self.core.update_device_metadata(
            device["device_id"],
            device_type="android",
            owner="Milan",
            expires_at="2026-12-31",
            notes="Telefono principale",
            tags=["personale", "android"],
        )
        self.assertEqual(updated["device_type"], "android")
        self.assertEqual(updated["owner"], "Milan")
        self.assertEqual(updated["tags"], ["android", "personale"])
        self.core.set_device_enabled(device["device_id"], False)
        self.assertFalse(self.core.list_devices()[0]["enabled"])
        self.core.set_device_enabled(device["device_id"], True)
        self.assertTrue(self.core.list_devices()[0]["enabled"])


if __name__ == "__main__":
    unittest.main()
