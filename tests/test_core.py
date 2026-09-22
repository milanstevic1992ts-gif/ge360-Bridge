import importlib
import os
import tempfile
import unittest


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name
        import ge360_bridge.core as core
        self.core = importlib.reload(core)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)

    def device(self):
        return {"name":"telefono","vpn_ip":"10.88.0.2","public_key":"p","preshared_key":"s","token":"t","enabled":True}

    def test_next_ip_skips_server(self):
        self.assertEqual(self.core.next_device_ip(), "10.88.0.2")

    def test_service_rejects_unknown_device(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_service("rilievi", 9888, "127.0.0.1", 9888, ["telefono"])

    def test_acl_maps_device_name_to_ip(self):
        self.core.save_devices([self.device()])
        s = self.core.register_service("rilievi", 9888, "127.0.0.1", 9888, ["telefono"])
        allowed = self.core.allowed_ips_for_service(s.__dict__, self.core.list_devices())
        self.assertEqual(allowed, {"10.88.0.2"})

    def test_grant_and_revoke_service_access(self):
        self.core.save_devices([self.device()])
        self.core.register_service("rilievi", 9888, "127.0.0.1", 9888, [])
        self.core.grant_device("rilievi", "telefono", True)
        self.assertEqual(self.core.list_services()[0]["allowed_devices"], ["telefono"])
        self.core.grant_device("rilievi", "telefono", False)
        self.assertEqual(self.core.list_services()[0]["allowed_devices"], [])


if __name__ == "__main__":
    unittest.main()
