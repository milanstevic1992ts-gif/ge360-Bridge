import importlib
import os
import tempfile
import unittest


class GuardrailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name
        import ge360_bridge.core as core
        self.core = importlib.reload(core)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)

    def test_reserved_dashboard_port_rejected(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_service("bad", 8789, "127.0.0.1", 9000, [])

    def test_reserved_pairing_port_rejected(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_service("bad-pairing", 8790, "127.0.0.1", 9000, [])

    def test_non_loopback_target_rejected(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_service("bad", 9000, "192.168.1.10", 9000, [])


if __name__ == "__main__":
    unittest.main()
