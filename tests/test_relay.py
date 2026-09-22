import importlib
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


class RelayServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "relay"
        self.state.mkdir()
        os.environ["GE360_RELAY_STATE_DIR"] = str(self.state)
        os.environ["GE360_RELAY_PUBLIC_HOST"] = "127.0.0.1"
        os.environ["GE360_RELAY_UDP_BIND"] = "127.0.0.1"
        os.environ["GE360_RELAY_UDP_START"] = "46000"
        os.environ["GE360_RELAY_UDP_END"] = "46199"
        os.environ["GE360_RELAY_IDLE_SECONDS"] = "90"
        import ge360_bridge.relay_server as relay_server
        self.relay = importlib.reload(relay_server)
        self.relay._sessions.clear()

    def tearDown(self):
        for session in list(self.relay._sessions.values()):
            session.stop()
        self.relay._sessions.clear()
        for key in (
            "GE360_RELAY_STATE_DIR",
            "GE360_RELAY_PUBLIC_HOST",
            "GE360_RELAY_UDP_BIND",
            "GE360_RELAY_UDP_START",
            "GE360_RELAY_UDP_END",
            "GE360_RELAY_IDLE_SECONDS",
        ):
            os.environ.pop(key, None)
        self.tmp.cleanup()

    def test_registry_stores_hash_only_and_authenticates_device(self):
        raw = "very-secret-device-token"
        result = self.relay.sync_devices([{
            "device_id": "dev_001",
            "token_sha256": self.relay.token_hash(raw),
            "enabled": True,
        }])
        self.assertEqual(result["devices"], 1)
        text = self.relay.REGISTRY_FILE.read_text(encoding="utf-8")
        self.assertNotIn(raw, text)
        self.assertTrue(self.relay.authenticate_device("dev_001", raw))
        self.assertFalse(self.relay.authenticate_device("dev_001", "wrong"))

    def test_session_uses_distinct_role_ports_and_forwards_opaque_udp(self):
        self.relay.sync_devices([{
            "device_id": "dev_001",
            "token_sha256": self.relay.token_hash("token"),
            "enabled": True,
        }])
        session = self.relay.create_session("dev_001", "127.0.0.1")
        self.assertNotEqual(session.bridge_port, session.client_port)
        session.activate_bridge("127.0.0.1")

        bridge_peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bridge_peer.bind(("127.0.0.1", 0))
        client_peer.bind(("127.0.0.1", 0))
        bridge_peer.settimeout(2)
        client_peer.settimeout(2)
        try:
            bridge_peer.sendto(b"bridge-prime", ("127.0.0.1", session.bridge_port))
            time.sleep(0.03)
            client_peer.sendto(b"client-prime", ("127.0.0.1", session.client_port))
            data, _ = bridge_peer.recvfrom(4096)
            self.assertEqual(data, b"client-prime")

            opaque = b"\x04\x00\x00\x00wireguard-ciphertext-not-decrypted"
            bridge_peer.sendto(opaque, ("127.0.0.1", session.bridge_port))
            data, _ = client_peer.recvfrom(4096)
            self.assertEqual(data, opaque)
            self.assertGreaterEqual(session.stats.bytes_bridge_to_client, len(opaque))
            self.assertGreaterEqual(session.stats.packets_bridge_to_client, 1)
        finally:
            bridge_peer.close()
            client_peer.close()
            session.stop()

    def test_status_explicitly_has_no_resource_catalog_or_decryption(self):
        status = self.relay.relay_status()
        self.assertFalse(status["payload_decryption"])
        self.assertFalse(status["resource_catalog"])
        self.assertFalse(status["multi_server_control_plane"])

    def test_device_request_reason_is_restricted(self):
        allowed = {"direct_failed", "p2p_failed", "control_unreachable"}
        self.assertNotIn("manual", allowed)
        self.assertNotIn("always", allowed)


class BridgeRelayClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "bridge"
        self.run = Path(self.tmp.name) / "run"
        self.state.mkdir()
        self.run.mkdir()
        os.environ["GE360_BRIDGE_STATE_DIR"] = str(self.state)
        os.environ["GE360_RELAY_TOKEN_FILE"] = str(self.state / "relay.token")
        os.environ["GE360_RELAY_RUNTIME_DIR"] = str(self.run)

        import ge360_bridge.core as core
        self.core = importlib.reload(core)
        self.core.BRIDGE_ENV.write_text(
            "RELAY_ENABLED=true\n"
            "RELAY_URL=https://relay.example:8792\n"
            "RELAY_CERT_SHA256=" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        (self.state / "relay.token").write_text("admin-token-" + "x" * 32, encoding="utf-8")
        self.device = {
            "device_id": "dev_001",
            "name": "telefono",
            "device_type": "android",
            "owner": "",
            "vpn_ip": "10.88.0.2",
            "public_key": "peer-public",
            "preshared_key": "psk",
            "token": "raw-device-token",
            "created_at": "2026-09-22T00:00:00+00:00",
            "expires_at": None,
            "notes": "",
            "tags": [],
            "enabled": True,
        }
        self.core.save_devices([self.device])
        import ge360_bridge.relay_client as relay_client
        self.client = importlib.reload(relay_client)

    def tearDown(self):
        for key in (
            "GE360_BRIDGE_STATE_DIR",
            "GE360_RELAY_TOKEN_FILE",
            "GE360_RELAY_RUNTIME_DIR",
        ):
            os.environ.pop(key, None)
        self.tmp.cleanup()

    def test_sync_payload_contains_token_hash_not_raw_token(self):
        payload = self.client.device_sync_payload()
        text = json.dumps(payload)
        self.assertNotIn("raw-device-token", text)
        self.assertEqual(
            payload["devices"][0]["token_sha256"],
            self.client.hashlib.sha256(b"raw-device-token").hexdigest(),
        )

    def test_public_config_never_contains_admin_token(self):
        public = self.client.relay_public_config()
        text = json.dumps(public)
        self.assertTrue(public["enabled"])
        self.assertNotIn("admin-token", text)
        self.assertNotIn("relay.token", text)

    def test_activate_request_updates_wireguard_runtime_and_acks_relay(self):
        commands = []
        def runner(args, timeout):
            commands.append(list(args))
            return subprocess.CompletedProcess(args, 0, "", "")

        request = {
            "session_id": "relay_test",
            "device_id": "dev_001",
            "bridge_endpoint": "relay.example:46001",
            "client_endpoint": "relay.example:46002",
        }
        with patch.object(
            self.client,
            "_relay_request",
            return_value={"status": "ACTIVE"},
        ) as api:
            result = self.client.activate_request(request, runner=runner)
        self.assertEqual(result["status"], "ACTIVE")
        self.assertTrue(any(cmd[:3] == ["wg", "set", "wg0"] for cmd in commands))
        self.assertTrue(any("relay.example:46001" in cmd for cmd in commands))
        api.assert_called_with("/v1/admin/activate", {"session_id": "relay_test"})

    def test_local_status_does_not_expose_admin_token(self):
        self.client._write_local_status({
            "configured": True,
            "active_sessions": [{"session_id": "relay_1", "status": "ACTIVE"}],
            "errors": [],
        })
        status = self.client.local_relay_status()
        self.assertNotIn("admin-token", json.dumps(status))
        self.assertEqual(len(status["runtime"]["active_sessions"]), 1)


if __name__ == "__main__":
    unittest.main()
