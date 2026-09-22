import importlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class P2PTraversalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.runtime = Path(self.tmp.name) / "run"
        self.state.mkdir()
        self.runtime.mkdir()
        os.environ["GE360_BRIDGE_STATE_DIR"] = str(self.state)
        os.environ["GE360_P2P_RUNTIME_DIR"] = str(self.runtime)

        import ge360_bridge.core as core
        self.core = importlib.reload(core)
        import ge360_bridge.pairing as pairing
        self.pairing = importlib.reload(pairing)
        import ge360_bridge.p2p as p2p
        self.p2p = importlib.reload(p2p)

        self.device = {
            "device_id": "dev_test",
            "name": "telefono",
            "device_type": "android",
            "owner": "",
            "vpn_ip": "10.88.0.2",
            "public_key": "peer-public-key",
            "preshared_key": "psk",
            "token": "device-token-secret",
            "created_at": "2026-09-22T00:00:00+00:00",
            "expires_at": None,
            "notes": "",
            "tags": [],
            "enabled": True,
        }
        self.core.save_devices([self.device])
        self.core.BRIDGE_ENV.write_text(
            "WG_PORT=51820\n"
            "PUBLIC_ENDPOINT=8.8.8.8:51820\n"
            "TRAVERSAL_ENABLED=true\n",
            encoding="utf-8",
        )
        self.p2p._SESSIONS.clear()
        self.p2p._DEVICE_ATTEMPTS.clear()

    def tearDown(self):
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)
        os.environ.pop("GE360_P2P_RUNTIME_DIR", None)
        self.tmp.cleanup()

    def test_authentication_requires_correct_device_token(self):
        device = self.p2p.authenticate_device("dev_test", "device-token-secret")
        self.assertEqual(device["vpn_ip"], "10.88.0.2")
        with self.assertRaises(self.core.BridgeError):
            self.p2p.authenticate_device("dev_test", "wrong")
        with self.assertRaises(self.core.BridgeError):
            self.p2p.authenticate_device("missing", "device-token-secret")

    def test_candidate_must_be_global_and_valid_port(self):
        candidate = self.p2p.validate_candidate("8.8.8.8", 53000, 51821)
        self.assertEqual(candidate.endpoint, "8.8.8.8:53000")
        with self.assertRaises(self.core.BridgeError):
            self.p2p.validate_candidate("192.168.1.2", 53000, 51821)
        with self.assertRaises(self.core.BridgeError):
            self.p2p.validate_candidate("8.8.8.8", 70000, 51821)

    def test_server_candidates_include_configured_public_endpoint_and_ipv6(self):
        original = self.p2p.global_ipv6_addresses
        self.p2p.global_ipv6_addresses = lambda: ["2001:4860:4860::8888"]
        try:
            candidates = self.p2p.server_candidates()
        finally:
            self.p2p.global_ipv6_addresses = original
        endpoints = [x["endpoint"] for x in candidates]
        self.assertIn("8.8.8.8:51820", endpoints)
        self.assertIn("[2001:4860:4860::8888]:51820", endpoints)

    def test_prepare_creates_runtime_only_session_without_token(self):
        result = self.p2p.prepare_traversal(
            "dev_test",
            "device-token-secret",
            candidate_ip="1.1.1.1",
            candidate_port=55000,
            candidate_local_port=51821,
            start_worker=False,
        )
        self.assertEqual(result["status"], "PREPARED")
        self.assertEqual(result["recommended_endpoint"], "8.8.8.8:51820")
        self.assertTrue(result["runtime_only"])
        self.assertFalse(result["relay_used"])
        self.assertNotIn("peer_public_key", result)
        self.assertNotIn("device_token", result)
        status = self.p2p.traversal_status("dev_test", "device-token-secret", result["session_id"])
        self.assertEqual(status["session_id"], result["session_id"])
        mirror = json.loads(self.p2p.SESSION_MIRROR.read_text(encoding="utf-8"))
        self.assertEqual(mirror[0]["session_id"], result["session_id"])
        self.assertNotIn("peer_public_key", mirror[0])
        self.assertNotIn("device_token", mirror[0])

    def test_prepare_is_rate_limited_per_device(self):
        for index in range(self.p2p.RATE_LIMIT_PER_DEVICE):
            self.p2p.prepare_traversal(
                "dev_test",
                "device-token-secret",
                candidate_ip="1.1.1.1",
                candidate_port=54000 + index,
                candidate_local_port=51821,
                start_worker=False,
            )
        with self.assertRaises(self.core.BridgeError):
            self.p2p.prepare_traversal(
                "dev_test",
                "device-token-secret",
                candidate_ip="1.1.1.1",
                candidate_port=56000,
                candidate_local_port=51821,
                start_worker=False,
            )

    def test_successful_attempt_observes_new_wireguard_handshake(self):
        prepared = self.p2p.prepare_traversal(
            "dev_test",
            "device-token-secret",
            candidate_ip="1.1.1.1",
            candidate_port=55000,
            candidate_local_port=51821,
            start_worker=False,
        )
        state = {"handshake_calls": 0, "commands": []}

        def runner(args, timeout):
            state["commands"].append(list(args))
            if args[:4] == ["wg", "show", "wg0", "endpoints"]:
                return subprocess.CompletedProcess(args, 0, "peer-public-key\t9.9.9.9:50000\n", "")
            if args[:4] == ["wg", "show", "wg0", "latest-handshakes"]:
                state["handshake_calls"] += 1
                value = 100 if state["handshake_calls"] == 1 else 9999999999
                return subprocess.CompletedProcess(args, 0, f"peer-public-key\t{value}\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        result = self.p2p.attempt_traversal(
            prepared["session_id"],
            runner=runner,
            sleeper=lambda _: None,
        )
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(result["endpoint_active"], "1.1.1.1:55000")
        commands = state["commands"]
        self.assertTrue(any(cmd[:3] == ["wg", "set", "wg0"] for cmd in commands))
        self.assertTrue(any(cmd[:1] == ["ping"] for cmd in commands))
        flattened = " ".join(" ".join(cmd) for cmd in commands)
        self.assertNotIn("upnpc", flattened)
        self.assertNotIn("relay", flattened.lower())

    def test_failed_attempt_restores_previous_endpoint(self):
        prepared = self.p2p.prepare_traversal(
            "dev_test",
            "device-token-secret",
            candidate_ip="1.1.1.1",
            candidate_port=55000,
            candidate_local_port=51821,
            start_worker=False,
        )
        commands = []

        def runner(args, timeout):
            commands.append(list(args))
            if args[:4] == ["wg", "show", "wg0", "endpoints"]:
                return subprocess.CompletedProcess(args, 0, "peer-public-key\t9.9.9.9:50000\n", "")
            if args[:4] == ["wg", "show", "wg0", "latest-handshakes"]:
                return subprocess.CompletedProcess(args, 0, "peer-public-key\t100\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        result = self.p2p.attempt_traversal(
            prepared["session_id"],
            runner=runner,
            sleeper=lambda _: None,
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["endpoint_restore"], "previous_endpoint_restored")
        self.assertTrue(any("9.9.9.9:50000" in cmd for cmd in commands))

    def test_status_explicitly_has_no_relay(self):
        status = self.p2p.p2p_status()
        self.assertFalse(status["relay_available"])
        self.assertFalse(status["relay_used"])
        self.assertFalse(status["phase20_started"])

    def test_traversal_can_be_disabled_from_bridge_env(self):
        self.core.BRIDGE_ENV.write_text(
            "WG_PORT=51820\nPUBLIC_ENDPOINT=8.8.8.8:51820\nTRAVERSAL_ENABLED=false\n",
            encoding="utf-8",
        )
        self.assertFalse(self.p2p.traversal_enabled())
        with self.assertRaises(self.core.BridgeError):
            self.p2p.prepare_traversal(
                "dev_test",
                "device-token-secret",
                candidate_ip="1.1.1.1",
                candidate_port=55000,
                start_worker=False,
            )


if __name__ == "__main__":
    unittest.main()
