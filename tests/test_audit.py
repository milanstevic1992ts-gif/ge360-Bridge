import importlib
import os
import sqlite3
import tempfile
import unittest


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"]=self.tmp.name
        import ge360_bridge.audit as audit
        self.audit=importlib.reload(audit)

    def tearDown(self):
        os.environ.pop("GE360_BRIDGE_STATE_DIR",None)
        self.tmp.cleanup()

    def test_write_and_list_event(self):
        event_id=self.audit.write_event(
            "RESOURCE_ACCESS",
            device_id="dev_1",
            device_name="telefono",
            resource="rilievi",
            action="tcp_connect",
            result="ALLOW",
            ip="10.88.0.2",
            latency_ms=12.345,
        )
        self.assertGreater(event_id,0)
        rows=self.audit.list_events(limit=10)
        self.assertEqual(len(rows),1)
        row=rows[0]
        self.assertEqual(row["event"],"RESOURCE_ACCESS")
        self.assertEqual(row["device_name"],"telefono")
        self.assertEqual(row["resource"],"rilievi")
        self.assertEqual(row["latency_ms"],12.35)

    def test_filters(self):
        self.audit.write_event("RESOURCE_ONLINE",resource="rilievi",result="ONLINE")
        self.audit.write_event("RESOURCE_OFFLINE",resource="marketing",result="OFFLINE")
        self.audit.write_event("ACL_CHANGED",device_name="telefono",resource="rilievi",action="device_override_allow")
        self.assertEqual(len(self.audit.list_events(event="RESOURCE_ONLINE")),1)
        self.assertEqual(len(self.audit.list_events(resource="rilievi")),2)
        self.assertEqual(len(self.audit.list_events(device="telefono")),1)

    def test_schema_has_no_payload_or_body_column(self):
        self.audit.init_db()
        with sqlite3.connect(str(self.audit.audit_db_path())) as db:
            columns=[row[1] for row in db.execute("PRAGMA table_info(audit_events)").fetchall()]
        self.assertNotIn("payload",columns)
        self.assertNotIn("body",columns)
        self.assertEqual(columns,[
            "id","timestamp","event","device_id","device_name","resource",
            "action","result","ip","latency_ms","error"
        ])

    def test_database_permissions_are_private(self):
        self.audit.init_db()
        mode=os.stat(self.audit.audit_db_path()).st_mode & 0o777
        self.assertEqual(mode,0o600)

    def test_unknown_event_rejected(self):
        with self.assertRaises(ValueError):
            self.audit.write_event("APP_PAYLOAD",result="bad")

    def test_core_acl_change_writes_audit(self):
        import ge360_bridge.core as core
        core=importlib.reload(core)
        core.save_devices([{
            "name":"telefono","vpn_ip":"10.88.0.2","public_key":"p",
            "preshared_key":"s","token":"t","enabled":True
        }])
        device=core.list_devices()[0]
        core.register_resource("rilievi",9888,"127.0.0.1",9888,[])
        core.set_device_access_override("rilievi",device["device_id"],"allow")
        rows=self.audit.list_events(event="ACL_CHANGED")
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["device_name"],"telefono")
        self.assertEqual(rows[0]["resource"],"rilievi")
        self.assertEqual(rows[0]["result"],"allow")


if __name__=="__main__":
    unittest.main()
