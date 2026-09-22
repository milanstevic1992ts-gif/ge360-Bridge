import importlib
import os
import tempfile
import unittest


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"]=self.tmp.name
        import ge360_bridge.metrics as metrics
        self.metrics=importlib.reload(metrics)

    def tearDown(self):
        os.environ.pop("GE360_BRIDGE_STATE_DIR",None)
        self.tmp.cleanup()

    def sample(self,ts,rx,tx,latency,state="ONLINE",connections=0,errors=0):
        self.metrics.persist_sample(
            ts_epoch=ts,
            device_rows=[{
                "device_id":"dev_1","device_name":"telefono","rx_bytes":rx,"tx_bytes":tx,
                "handshake_age_seconds":30,"connected":True,
            }],
            resource_rows=[{
                "resource":"rilievi","state":state,"latency_ms":latency,
                "error":None if state=="ONLINE" else "bad",
            }],
            bridge_row={
                "uptime_seconds":ts,
                "connections_total":connections,
                "errors_total":errors,
            },
        )

    def test_parse_wg_dump(self):
        dump=(
            "priv\tpub\t51820\toff\n"
            "peer\tpsk\t1.2.3.4:9\t10.88.0.2/32\t900\t1000\t2000\t25\n"
        )
        out=self.metrics.parse_wg_dump(dump,now_epoch=1000)
        self.assertEqual(out["peer"]["rx_bytes"],1000)
        self.assertEqual(out["peer"]["tx_bytes"],2000)
        self.assertEqual(out["peer"]["handshake_age_seconds"],100)
        self.assertTrue(out["peer"]["connected"])

    def test_query_series_uses_rx_tx_deltas(self):
        self.sample(1000,1000,2000,10,connections=10,errors=1)
        self.sample(1060,1300,2600,20,connections=12,errors=2)
        data=self.metrics.query_series("1h",now_epoch=1100)
        points=data["devices"]["dev_1"]
        self.assertEqual(sum(x["rx_bytes"] for x in points),300)
        self.assertEqual(sum(x["tx_bytes"] for x in points),600)
        self.assertEqual(sum(x["connections"] for x in data["bridge"]),2)
        self.assertEqual(sum(x["errors"] for x in data["bridge"]),1)

    def test_resource_latency_and_errors(self):
        self.sample(1000,0,0,10,"ONLINE")
        self.sample(1060,0,0,30,"OFFLINE")
        data=self.metrics.query_series("1h",resource="rilievi",now_epoch=1100)
        points=data["resources"]["rilievi"]
        self.assertEqual(sum(x["errors"] for x in points),1)
        lat=[x["latency_ms"] for x in points if x["latency_ms"] is not None]
        self.assertEqual(lat,[10.0,30.0])

    def test_device_filter(self):
        self.sample(1000,100,100,10)
        data=self.metrics.query_series("1h",device="missing",now_epoch=1100)
        self.assertEqual(data["devices"],{})

    def test_invalid_window(self):
        with self.assertRaises(ValueError):
            self.metrics.query_series("2h")

    def test_retention_removes_older_than_35_days(self):
        self.sample(100,0,0,10)
        new_ts=100+self.metrics.RETENTION_SECONDS+10
        self.sample(new_ts,0,0,10)
        with self.metrics.connect() as db:
            old=db.execute("SELECT COUNT(*) FROM bridge_samples WHERE ts_epoch=100").fetchone()[0]
        self.assertEqual(old,0)

    def test_database_permissions_private(self):
        self.metrics.init_db()
        mode=os.stat(self.metrics.metrics_db_path()).st_mode & 0o777
        self.assertEqual(mode,0o600)


if __name__=="__main__":
    unittest.main()
