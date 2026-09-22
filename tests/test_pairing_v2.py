import base64
import importlib
import json
import os
import tempfile
import time
import unittest


class PairingV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name
        import ge360_bridge.core as core
        self.core = importlib.reload(core)
        import ge360_bridge.pairing as pairing
        self.pairing = importlib.reload(pairing)
        self.pairing.generate_psk = lambda: "test-psk"
        (self.core.STATE_DIR / "server.pub").write_text("server-public-key\n", encoding="utf-8")
        (self.core.STATE_DIR / "bridge.env").write_text(
            "PUBLIC_ENDPOINT=example.test:51820\nPAIRING_PORT=8790\n",
            encoding="utf-8",
        )
        self.public_key = base64.b64encode(b"A" * 32).decode()

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)

    def test_token_is_not_stored_in_plaintext(self):
        record, token = self.pairing.create_enrollment("telefono", ttl_seconds=600)
        raw = self.pairing.ENROLLMENTS_FILE.read_text(encoding="utf-8")
        self.assertNotIn(token, raw)
        self.assertIn("token_hash", raw)
        self.assertEqual(record["status"], "pending")

    def test_client_public_key_creates_device_and_no_private_key_is_received(self):
        record, token = self.pairing.create_enrollment("telefono", device_type="android")
        result = self.pairing.consume_enrollment(record["enrollment_id"], token, self.public_key)
        device = self.core.list_devices()[0]
        self.assertEqual(device["public_key"], self.public_key)
        self.assertEqual(device["preshared_key"], "test-psk")
        self.assertEqual(result["vpn_ip"], "10.88.0.2")
        stored = json.loads(self.pairing.ENROLLMENTS_FILE.read_text(encoding="utf-8"))[0]
        self.assertEqual(stored["status"], "used")
        self.assertNotIn("private_key", json.dumps(result))
        self.assertNotIn("private_key", json.dumps(device))

    def test_replay_is_rejected(self):
        record, token = self.pairing.create_enrollment("telefono")
        self.pairing.consume_enrollment(record["enrollment_id"], token, self.public_key)
        with self.assertRaises(self.core.BridgeError):
            self.pairing.consume_enrollment(record["enrollment_id"], token, self.public_key)

    def test_wrong_token_is_rejected(self):
        record, _token = self.pairing.create_enrollment("telefono")
        with self.assertRaises(self.core.BridgeError):
            self.pairing.consume_enrollment(record["enrollment_id"], "wrong-token", self.public_key)
        self.assertEqual(self.core.list_devices(), [])

    def test_expired_token_is_rejected(self):
        record, token = self.pairing.create_enrollment("telefono")
        items = self.pairing._load_enrollments()
        items[0]["expires_at"] = int(time.time()) - 1
        self.pairing._save_enrollments(items)
        with self.assertRaises(self.core.BridgeError):
            self.pairing.consume_enrollment(record["enrollment_id"], token, self.public_key)
        self.assertEqual(self.core.list_devices(), [])

    def test_initial_group_assignment_happens_after_enrollment(self):
        self.core.create_group("amministratori")
        record, token = self.pairing.create_enrollment(
            "telefono", group_names=["amministratori"]
        )
        result = self.pairing.consume_enrollment(record["enrollment_id"], token, self.public_key)
        device = self.core.list_devices()[0]
        group = self.core.list_groups()[0]
        self.assertIn(device["device_id"], group["device_ids"])
        self.assertEqual(result["groups"], ["amministratori"])

    def test_duplicate_pending_pairing_for_same_name_is_rejected(self):
        self.pairing.create_enrollment("telefono")
        with self.assertRaises(self.core.BridgeError):
            self.pairing.create_enrollment("telefono")

    def test_public_key_validation_requires_wireguard_size(self):
        with self.assertRaises(self.core.BridgeError):
            self.pairing.validate_wireguard_public_key(base64.b64encode(b"short").decode())


if __name__ == "__main__":
    unittest.main()
