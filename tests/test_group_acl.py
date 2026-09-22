import importlib
import os
import tempfile
import unittest


class GroupAclTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name
        import ge360_bridge.core as core
        self.core = importlib.reload(core)
        self.core.save_devices([{
            "name":"telefono","vpn_ip":"10.88.0.2","public_key":"p",
            "preshared_key":"s","token":"t","enabled":True
        }])
        self.device = self.core.list_devices()[0]
        self.core.register_service("rilievi",9888,"127.0.0.1",9888,[])

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR",None)

    def test_group_grants_service_by_device_id(self):
        self.core.create_group("amministratori")
        self.core.set_group_device("amministratori",self.device["device_id"],True)
        self.core.set_group_service("amministratori","rilievi",True)
        service=self.core.list_services()[0]
        self.assertTrue(self.core.service_allows_device(service,self.device))
        self.assertEqual(self.core.allowed_ips_for_service(service,self.core.list_devices()),{"10.88.0.2"})

    def test_direct_deny_overrides_group_allow(self):
        self.core.create_group("amministratori")
        self.core.set_group_device("amministratori",self.device["device_id"],True)
        self.core.set_group_service("amministratori","rilievi",True)
        self.core.set_device_access_override("rilievi",self.device["device_id"],"deny")
        service=self.core.list_services()[0]
        self.assertFalse(self.core.service_allows_device(service,self.device))
        self.assertEqual(self.core.service_access_source(service,self.device),"deny_override")

    def test_direct_allow_overrides_no_group(self):
        self.core.set_device_access_override("rilievi",self.device["device_id"],"allow")
        service=self.core.list_services()[0]
        self.assertTrue(self.core.service_allows_device(service,self.device))
        self.assertEqual(self.core.service_access_source(service,self.device),"allow_override")

    def test_inherit_clears_direct_override(self):
        self.core.set_device_access_override("rilievi",self.device["device_id"],"deny")
        self.core.set_device_access_override("rilievi",self.device["device_id"],"inherit")
        service=self.core.list_services()[0]
        self.assertNotIn("telefono",service["allowed_devices"])
        self.assertNotIn("telefono",service["denied_devices"])
        self.assertFalse(self.core.service_allows_device(service,self.device))

    def test_rename_does_not_break_group_membership_and_updates_overrides(self):
        self.core.create_group("staff")
        self.core.set_group_device("staff",self.device["device_id"],True)
        self.core.set_device_access_override("rilievi","telefono","allow")
        self.core.rename_device(self.device["device_id"],"telefono-milan")
        group=self.core.list_groups()[0]
        service=self.core.list_services()[0]
        self.assertIn(self.device["device_id"],group["device_ids"])
        self.assertIn("telefono-milan",service["allowed_devices"])
        self.assertNotIn("telefono",service["allowed_devices"])

    def test_disabled_group_stops_inherited_access(self):
        self.core.create_group("staff")
        self.core.set_group_device("staff",self.device["device_id"],True)
        self.core.set_group_service("staff","rilievi",True)
        self.core.set_group_enabled("staff",False)
        service=self.core.list_services()[0]
        self.assertFalse(self.core.service_allows_device(service,self.device))


if __name__=="__main__":
    unittest.main()
