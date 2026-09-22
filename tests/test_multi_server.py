import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class MultiServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.state = root / "bridge"
        self.state.mkdir()
        os.environ["GE360_BRIDGE_STATE_DIR"] = str(self.state)
        os.environ["GE360_SERVER_REGISTRY_FILE"] = str(self.state / "servers.json")
        os.environ["GE360_SERVER_ID_FILE"] = str(self.state / "server-id")
        os.environ["GE360_SERVER_TOKEN_FILE"] = str(self.state / "server.token")
        import ge360_bridge.core as core
        self.core = importlib.reload(core)
        import ge360_bridge.multi_server as multi_server
        self.ms = importlib.reload(multi_server)

    def tearDown(self):
        for key in (
            "GE360_BRIDGE_STATE_DIR",
            "GE360_SERVER_REGISTRY_FILE",
            "GE360_SERVER_ID_FILE",
            "GE360_SERVER_TOKEN_FILE",
        ):
            os.environ.pop(key, None)
        self.tmp.cleanup()

    def snapshot(self, hostname="node-a", resource="rilievi"):
        return {
            "agent": {"version": "0.23.0", "read_only": True},
            "host": {"hostname": hostname, "os": "Debian", "architecture": "x86_64", "uptime_seconds": 100},
            "ip_addresses": [{"address": "10.20.30.40"}],
            "resources": [{
                "name": resource,
                "display_name": resource.title(),
                "version": "1",
                "icon": "server",
                "description": "Remote",
                "protocol": "http",
                "target_host": "127.0.0.1",
                "target_port": 9888,
                "health_state": "ONLINE",
                "latency_ms": 3.2,
                "enabled": True,
            }],
            "generated_at": "2026-09-22T20:00:00+00:00",
        }

    def test_server_registry_redacts_tokens_by_default(self):
        item = self.ms.add_server(
            "debian2",
            "https://10.0.0.20:8793",
            "a" * 64,
            "token_" + "x" * 40,
            server_id="srv_debian2",
        )
        self.assertNotIn("token", item)
        public = self.ms.list_servers()
        self.assertNotIn("token", public[0])
        self.assertNotIn("control_url", public[0])
        self.assertNotIn("tls_cert_sha256", public[0])
        private = self.ms.list_servers(include_secrets=True)
        self.assertTrue(private[0]["token"].startswith("token_"))
        self.assertEqual((self.state / "servers.json").stat().st_mode & 0o777, 0o600)

    def test_duplicate_server_identity_is_rejected(self):
        self.ms.add_server("a", "https://10.0.0.2:8793", "a" * 64, "x" * 40, server_id="srv_node_a")
        with self.assertRaises(Exception):
            self.ms.add_server("b", "https://10.0.0.3:8793", "b" * 64, "y" * 40, server_id="srv_node_a")

    def test_control_url_requires_https(self):
        with self.assertRaises(Exception):
            self.ms.add_server("bad", "http://10.0.0.2:8793", "a" * 64, "x" * 40, server_id="srv_bad")

    def test_sanitize_snapshot_removes_target_host_and_unknown_fields(self):
        raw = self.snapshot()
        raw["resources"][0]["secret"] = "do-not-copy"
        clean = self.ms.sanitize_agent_snapshot(raw)
        resource = clean["resources"][0]
        self.assertNotIn("target_host", resource)
        self.assertNotIn("secret", resource)
        self.assertEqual(resource["health_state"], "ONLINE")

    def test_catalog_namespaces_same_resource_name_by_server(self):
        self.ms.add_server("server-a", "https://10.0.0.2:8793", "a" * 64, "x" * 40, server_id="srv_node_a")
        self.ms.add_server("server-b", "https://10.0.0.3:8793", "b" * 64, "y" * 40, server_id="srv_node_b")
        with patch.object(self.ms, "local_server_id", return_value="srv_local"):
            catalog = self.ms.build_catalog(
                local_snapshot=self.snapshot("local", "rilievi"),
                remote_snapshots={
                    "srv_node_a": self.snapshot("node-a", "rilievi"),
                    "srv_node_b": self.snapshot("node-b", "rilievi"),
                },
            )
        ids = {x["resource_id"] for x in catalog["resources"]}
        self.assertIn("srv_local:rilievi", ids)
        self.assertIn("srv_node_a:rilievi", ids)
        self.assertIn("srv_node_b:rilievi", ids)
        self.assertFalse(catalog["remote_mutation"])
        self.assertFalse(catalog["remote_resource_proxy"])

    def test_offline_remote_server_does_not_hide_other_servers(self):
        self.ms.add_server("good", "https://10.0.0.2:8793", "a" * 64, "x" * 40, server_id="srv_good")
        self.ms.add_server("bad", "https://10.0.0.3:8793", "b" * 64, "y" * 40, server_id="srv_bad")
        def fetcher(server):
            if server["server_id"] == "srv_bad":
                raise self.core.BridgeError("offline")
            return self.snapshot("good", "firefly")
        with patch.object(self.ms, "local_server_id", return_value="srv_local"):
            catalog = self.ms.build_catalog(local_snapshot=self.snapshot("local", "rilievi"), fetcher=fetcher)
        servers = {x["server_id"]: x for x in catalog["servers"]}
        self.assertTrue(servers["srv_good"]["online"])
        self.assertFalse(servers["srv_bad"]["online"])
        self.assertEqual(servers["srv_bad"]["error"], "offline")
        self.assertIn("srv_good:firefly", {x["resource_id"] for x in catalog["resources"]})

    def test_catalog_never_contains_server_tokens(self):
        secret = "super-secret-server-token-" + "z" * 32
        self.ms.add_server("remote", "https://10.0.0.2:8793", "a" * 64, secret, server_id="srv_remote")
        with patch.object(self.ms, "local_server_id", return_value="srv_local"):
            catalog = self.ms.build_catalog(
                local_snapshot=self.snapshot("local", "rilievi"),
                remote_snapshots={"srv_remote": self.snapshot("remote", "firefly")},
            )
        rendered = json.dumps(catalog)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("https://10.0.0.2:8793", rendered)
        self.assertNotIn("a" * 64, rendered)

    def test_local_identity_and_token_are_persistent_and_private(self):
        server_id = self.ms.local_server_id()
        token = self.ms.local_server_token()
        self.assertEqual(server_id, self.ms.local_server_id())
        self.assertEqual(token, self.ms.local_server_token())
        self.assertTrue(server_id.startswith("srv_"))
        self.assertGreaterEqual(len(token), 32)
        self.assertEqual((self.state / "server-id").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.state / "server.token").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
