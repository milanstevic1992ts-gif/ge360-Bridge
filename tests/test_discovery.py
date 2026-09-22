import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


VALID = {
    "name": "GE360 Rilievi",
    "type": "rilievi",
    "version": "4.2",
    "health": "/healthz",
}


class BackendDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name
        import ge360_bridge.core as core
        import ge360_bridge.discovery as discovery
        self.core = importlib.reload(core)
        self.discovery = importlib.reload(discovery)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)

    def test_manifest_schema_is_strict_and_canonical(self):
        out = self.discovery.validate_manifest({**VALID, "schema": 1, "icon": "ruler"})
        self.assertEqual(out["type"], "rilievi")
        self.assertEqual(out["schema"], 1)
        self.assertEqual(out["icon"], "ruler")
        with self.assertRaises(self.core.BridgeError):
            self.discovery.validate_manifest({**VALID, "extra": "no"})
        with self.assertRaises(self.core.BridgeError):
            self.discovery.validate_manifest({**VALID, "health": "http://192.168.1.10/healthz"})
        with self.assertRaises(self.core.BridgeError):
            self.discovery.validate_manifest({**VALID, "schema": 2})

    def test_non_loopback_host_is_rejected(self):
        with self.assertRaises(self.core.BridgeError):
            self.discovery.discover_backends([9001], host="192.168.1.10")

    def test_discovery_only_probes_selected_loopback_ports(self):
        seen = []
        def fake_probe(host, port, **kwargs):
            seen.append((host, port, kwargs["scheme"]))
            return dict(VALID)
        with patch.object(self.discovery, "probe_manifest", side_effect=fake_probe):
            result = self.discovery.discover_backends([9002, 9001], host="127.0.0.1")
        self.assertEqual(sorted(seen), [("127.0.0.1", 9001, "http"), ("127.0.0.1", 9002, "http")])
        self.assertEqual([p["target_port"] for p in result["proposals"]], [9001, 9002])

    def test_auto_discovery_skips_bridge_system_ports(self):
        seen = []
        def fake_probe(host, port, **kwargs):
            seen.append(port)
            return dict(VALID)
        with patch.object(self.discovery, "loopback_listener_ports", return_value=[8788, 8789, 8790, 9001]):
            with patch.object(self.discovery, "probe_manifest", side_effect=fake_probe):
                result = self.discovery.discover_backends()
        self.assertEqual(seen, [9001])
        self.assertEqual(result["scanned_ports"], [9001])

    def test_proc_parser_accepts_only_exact_ipv4_loopback_listener(self):
        proc = Path(self.tmp.name) / "tcp"
        proc.write_text(
            "  sl  local_address rem_address   st\n"
            "   0: 0100007F:2329 00000000:0000 0A\n"
            "   1: 00000000:232A 00000000:0000 0A\n"
            "   2: 0100007F:232B 00000000:0000 01\n",
            encoding="ascii",
        )
        self.assertEqual(self.discovery._proc_ipv4_loopback_ports(proc), [9001])

    def test_existing_resource_is_never_overwritten(self):
        self.core.register_resource("rilievi", 9100, "127.0.0.1", 9100, [])
        with patch.object(self.discovery, "probe_manifest", return_value=dict(VALID)):
            result = self.discovery.discover_backends([9001])
            self.assertEqual(result["proposals"][0]["status"], "name_conflict")
            with self.assertRaises(self.core.BridgeError):
                self.discovery.import_discovered_backend(
                    host="127.0.0.1",
                    target_port=9001,
                    bridge_port=9002,
                )
        current = self.core.find_resource("rilievi")
        self.assertEqual(current["target_port"], 9100)

    def test_import_registers_via_existing_resource_registry(self):
        manifest = {**VALID, "icon": "ruler", "description": "Rilievi automatici"}
        with patch.object(self.discovery, "probe_manifest", return_value=manifest):
            resource = self.discovery.import_discovered_backend(
                host="127.0.0.1",
                target_port=9001,
                bridge_port=9002,
            )
        self.assertEqual(resource.name, "rilievi")
        stored = self.core.find_resource("rilievi")
        self.assertEqual(stored["bridge_port"], 9002)
        self.assertEqual(stored["target_host"], "127.0.0.1")
        self.assertEqual(stored["target_port"], 9001)
        self.assertEqual(stored["protocol"], "http")
        self.assertEqual(stored["health_url"], "/healthz")
        self.assertEqual(stored["description"], "Rilievi automatici")
        self.assertEqual(
            self.core.RESOURCES_FILE.read_text(encoding="utf-8"),
            self.core.SERVICES_FILE.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
