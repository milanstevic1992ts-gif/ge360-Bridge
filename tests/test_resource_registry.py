import importlib
import json
import os
import tempfile
import unittest


class ResourceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name
        import ge360_bridge.core as core
        self.core = importlib.reload(core)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)

    def device(self):
        return {
            "name":"telefono",
            "vpn_ip":"10.88.0.2",
            "public_key":"p",
            "preshared_key":"s",
            "token":"t",
            "enabled":True,
        }

    def test_legacy_service_migrates_to_resource_without_losing_acl(self):
        legacy=[{
            "name":"rilievi",
            "listen_port":9888,
            "target_host":"127.0.0.1",
            "target_port":9888,
            "allowed_devices":["telefono"],
            "denied_devices":[],
            "enabled":True,
        }]
        self.core._atomic_write(self.core.SERVICES_FILE, legacy)
        changed=self.core.upgrade_resource_registry()
        self.assertGreaterEqual(changed,1)
        r=self.core.list_resources()[0]
        self.assertEqual(r["name"],"rilievi")
        self.assertEqual(r["bridge_port"],9888)
        self.assertEqual(r["listen_port"],9888)
        self.assertEqual(r["target_host"],"127.0.0.1")
        self.assertEqual(r["target_port"],9888)
        self.assertEqual(r["allowed_devices"],["telefono"])
        self.assertEqual(r["protocol"],"tcp")
        self.assertEqual(r["icon"],"server")
        self.assertEqual(r["description"],"")
        self.assertEqual(r["health_url"],"")
        self.assertEqual(r["timeout_seconds"],2.0)
        self.assertTrue(self.core.RESOURCES_FILE.exists())

    def test_resource_registry_mirrors_legacy_services_file(self):
        self.core.register_resource("rilievi",9888,"127.0.0.1",9888,[])
        resources=json.loads(self.core.RESOURCES_FILE.read_text())
        services=json.loads(self.core.SERVICES_FILE.read_text())
        self.assertEqual(resources,services)
        self.assertEqual(self.core.list_services(),self.core.list_resources())

    def test_register_full_http_resource(self):
        r=self.core.register_resource(
            "rilievi",9888,"127.0.0.1",9888,[],
            icon="ruler",
            description="GE360 Rilievi",
            protocol="http",
            health_url="/healthz",
            timeout_seconds=3.5,
        )
        self.assertEqual(r.protocol,"http")
        stored=self.core.find_resource("rilievi")
        self.assertEqual(stored["icon"],"ruler")
        self.assertEqual(stored["description"],"GE360 Rilievi")
        self.assertEqual(stored["health_url"],"/healthz")
        self.assertEqual(stored["timeout_seconds"],3.5)

    def test_resource_update_preserves_acl(self):
        self.core.save_devices([self.device()])
        self.core.register_resource("rilievi",9888,"127.0.0.1",9888,["telefono"])
        self.core.update_resource(
            "rilievi",
            protocol="http",
            icon="ruler",
            description="Rilievi",
            health_url="/healthz",
            timeout_seconds=4,
        )
        r=self.core.find_resource("rilievi")
        self.assertEqual(r["allowed_devices"],["telefono"])
        self.assertEqual(r["protocol"],"http")
        self.assertEqual(r["health_url"],"/healthz")

    def test_resource_remove_cleans_group_acl(self):
        self.core.save_devices([self.device()])
        self.core.register_resource("rilievi",9888,"127.0.0.1",9888,[])
        self.core.create_group("staff")
        self.core.set_group_resource("staff","rilievi",True)
        self.assertIn("rilievi",self.core.list_groups()[0]["allowed_resources"])
        self.core.remove_resource("rilievi")
        group=self.core.list_groups()[0]
        self.assertEqual(group["allowed_resources"],[])
        self.assertEqual(group["allowed_services"],[])

    def test_invalid_protocol_rejected(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_resource("bad",9001,"127.0.0.1",9001,[],protocol="udp")

    def test_health_url_cannot_point_to_lan(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_resource(
                "bad",9001,"127.0.0.1",9001,[],
                protocol="http",
                health_url="http://192.168.1.50:9001/healthz",
            )

    def test_health_url_full_form_must_match_target_port(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_resource(
                "bad",9001,"127.0.0.1",9001,[],
                protocol="http",
                health_url="http://127.0.0.1:9999/healthz",
            )


if __name__=="__main__":
    unittest.main()
