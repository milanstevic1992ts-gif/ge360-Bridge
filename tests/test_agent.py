import importlib
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class LinuxAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_AGENT_STATE_DIR"] = self.tmp.name
        import ge360_bridge.agent as agent
        self.agent = importlib.reload(agent)
        self.agent.clear_snapshot_cache()

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_AGENT_STATE_DIR", None)

    def test_memory_metrics_from_proc_format(self):
        path = Path(self.tmp.name) / "meminfo"
        path.write_text(
            "MemTotal:       1000 kB\n"
            "MemAvailable:    400 kB\n"
            "SwapTotal:       200 kB\n"
            "SwapFree:        150 kB\n",
            encoding="utf-8",
        )
        data = self.agent.memory_metrics(path)
        self.assertEqual(data["total_bytes"], 1000 * 1024)
        self.assertEqual(data["available_bytes"], 400 * 1024)
        self.assertEqual(data["used_bytes"], 600 * 1024)
        self.assertEqual(data["swap_free_bytes"], 150 * 1024)

    def test_network_metrics_excludes_loopback(self):
        path = Path(self.tmp.name) / "dev"
        path.write_text(
            "Inter-| Receive | Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
            "    lo: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n"
            "  eth0: 100 0 0 0 0 0 0 0 250 0 0 0 0 0 0 0\n",
            encoding="utf-8",
        )
        data = self.agent.network_metrics(path)
        self.assertEqual(data["rx_bytes"], 100)
        self.assertEqual(data["tx_bytes"], 250)
        self.assertEqual(data["interfaces"], [{"name": "eth0", "rx_bytes": 100, "tx_bytes": 250}])

    def test_local_resources_reuses_phase13_manifest(self):
        proposal = {
            "resource_name": "rilievi",
            "target_host": "127.0.0.1",
            "target_port": 9888,
            "protocol": "http",
            "manifest": {
                "name": "GE360 Rilievi",
                "type": "rilievi",
                "version": "4.2",
                "health": "/healthz",
                "icon": "ruler",
                "description": "Rilievi",
            },
        }
        with patch.object(self.agent, "discover_backends", return_value={"proposals": [proposal]}):
            resources = self.agent.local_resources()
        self.assertEqual(len(resources), 1)
        resource = resources[0]
        self.assertEqual(resource["name"], "rilievi")
        self.assertEqual(resource["display_name"], "GE360 Rilievi")
        self.assertEqual(resource["target_host"], "127.0.0.1")
        self.assertEqual(resource["target_port"], 9888)
        self.assertEqual(resource["health_url"], "/healthz")

    def test_snapshot_contains_required_phase14_sections(self):
        resources = [{
            "name": "rilievi",
            "display_name": "GE360 Rilievi",
            "version": "4.2",
            "icon": "ruler",
            "description": "",
            "protocol": "http",
            "target_host": "127.0.0.1",
            "target_port": 9888,
            "health_url": "/healthz",
            "timeout_seconds": 2.0,
            "enabled": True,
        }]
        health = [{
            "name": "rilievi",
            "state": "ONLINE",
            "latency_ms": 2.5,
            "checks": {},
        }]
        with patch.object(self.agent, "local_resources", return_value=resources),              patch.object(self.agent, "check_resources", return_value=health),              patch.object(self.agent, "health_summary", return_value={"ONLINE": 1}),              patch.object(self.agent, "host_status", return_value={"hostname": "node-a"}),              patch.object(self.agent, "ip_addresses", return_value=[{"address": "10.0.0.2"}]),              patch.object(self.agent, "host_metrics", return_value={"uptime_seconds": 10}):
            snapshot = self.agent.build_snapshot(use_cache=False)
        self.assertTrue(snapshot["agent"]["read_only"])
        self.assertEqual(snapshot["host"]["hostname"], "node-a")
        self.assertEqual(snapshot["resources"][0]["health_state"], "ONLINE")
        self.assertTrue(snapshot["resource_discovery"]["ok"])
        self.assertEqual(snapshot["health"]["summary"]["ONLINE"], 1)
        self.assertEqual(snapshot["ip_addresses"][0]["address"], "10.0.0.2")
        self.assertEqual(snapshot["metrics"]["uptime_seconds"], 10)

    def test_token_validation(self):
        path = Path(self.tmp.name) / "token"
        path.write_text("x" * 40 + "\n", encoding="utf-8")
        self.assertEqual(self.agent.load_agent_token(path), "x" * 40)
        path.write_text("short\n", encoding="utf-8")
        with self.assertRaises(Exception):
            self.agent.load_agent_token(path)

    def test_api_requires_bearer_for_private_endpoints(self):
        token = "a" * 40
        snapshot = {
            "agent": {"name": "GE360 Linux Agent", "version": "0.16.0", "api_version": 1, "read_only": True},
            "host": {"hostname": "node-a"},
            "ip_addresses": [],
            "resources": [],
            "resource_discovery": {"ok": True, "error": None},
            "health": {"summary": {}, "resources": []},
            "metrics": {"uptime_seconds": 1},
            "generated_at": "2026-09-22T00:00:00+00:00",
        }
        server = self.agent.AgentServer(
            ("127.0.0.1", 0),
            self.agent.AgentHandler,
            agent_token=token,
            discovery_timeout=0.1,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with urlopen(base + "/healthz", timeout=2) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(HTTPError) as denied:
                urlopen(base + "/v1/status", timeout=2)
            self.assertEqual(denied.exception.code, 401)

            request = Request(base + "/v1/status", headers={"Authorization": "Bearer " + token})
            with patch.object(self.agent, "build_snapshot", return_value=snapshot):
                with urlopen(request, timeout=2) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            self.assertEqual(payload["host"]["hostname"], "node-a")
            self.assertEqual(payload["resource_count"], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_bind_rejects_dns_names(self):
        self.assertEqual(self.agent.validate_bind("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(Exception):
            self.agent.validate_bind("example.com")


if __name__ == "__main__":
    unittest.main()
