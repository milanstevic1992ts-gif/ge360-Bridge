import unittest
from unittest.mock import patch

from ge360_bridge.dashboard import human_age, parse_wg_dump


class DashboardTests(unittest.TestCase):
    def test_parse_wg_dump_maps_peer(self):
        dump = (
            "serverpriv\tserverpub\t51820\toff\n"
            "peerpub\tpsk\t1.2.3.4:5555\t10.88.0.2/32\t1000\t2048\t4096\t25\n"
        )
        with patch("ge360_bridge.dashboard.time.time", return_value=1100):
            peers = parse_wg_dump(dump)
        self.assertEqual(peers["peerpub"]["handshake_age_seconds"], 100)
        self.assertTrue(peers["peerpub"]["online"])
        self.assertEqual(peers["peerpub"]["rx_bytes"], 2048)

    def test_human_age(self):
        self.assertEqual(human_age(None), "mai")
        self.assertEqual(human_age(30), "30s fa")
        self.assertEqual(human_age(120), "2 min fa")


if __name__ == "__main__":
    unittest.main()
