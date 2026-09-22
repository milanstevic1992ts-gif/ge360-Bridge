import importlib
import ipaddress
import json
import os
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch


class NatDiscoveryTests(unittest.TestCase):
    def setUp(self):
        import ge360_bridge.nat_discovery as nat
        self.nat = importlib.reload(nat)

    def xor_addr(self, ip, port, txid):
        cookie = self.nat.STUN_MAGIC_COOKIE
        packed = ipaddress.IPv4Address(ip).packed
        xor_ip = bytes(a ^ b for a, b in zip(packed, struct.pack("!I", cookie)))
        return struct.pack("!BBH", 0, 1, port ^ (cookie >> 16)) + xor_ip

    def plain_addr(self, ip, port):
        return struct.pack("!BBH", 0, 1, port) + ipaddress.IPv4Address(ip).packed

    def response(self, txid, attrs):
        raw = b""
        for typ, value in attrs:
            raw += struct.pack("!HH", typ, len(value)) + value
            raw += b"\x00" * ((4 - len(value) % 4) % 4)
        return struct.pack(
            "!HHI12s",
            self.nat.STUN_BINDING_SUCCESS,
            len(raw),
            self.nat.STUN_MAGIC_COOKIE,
            txid,
        ) + raw

    def test_parse_default_server_and_validation(self):
        self.assertEqual(
            self.nat.parse_stun_server("stun.cloudflare.com:3478"),
            ("stun.cloudflare.com", 3478),
        )
        self.assertEqual(self.nat.parse_stun_server("203.0.113.5"), ("203.0.113.5", 3478))
        with self.assertRaises(Exception):
            self.nat.parse_stun_server("../bad:3478")
        with self.assertRaises(Exception):
            self.nat.parse_stun_server("example.com:70000")

    def test_parse_xor_mapped_and_rfc5780_other_address(self):
        txid = b"0123456789ab"
        data = self.response(txid, [
            (
                self.nat.ATTR_XOR_MAPPED_ADDRESS,
                self.xor_addr("198.51.100.44", 45678, txid),
            ),
            (
                self.nat.ATTR_RESPONSE_ORIGIN,
                self.plain_addr("203.0.113.10", 3478),
            ),
            (
                self.nat.ATTR_OTHER_ADDRESS,
                self.plain_addr("203.0.113.11", 3479),
            ),
        ])
        parsed = self.nat.parse_stun_response(data, txid)
        self.assertEqual(parsed["mapped_ip"], "198.51.100.44")
        self.assertEqual(parsed["mapped_port"], 45678)
        self.assertEqual(parsed["response_origin"], ("203.0.113.10", 3478))
        self.assertEqual(parsed["other_address"], ("203.0.113.11", 3479))

    def test_response_rejects_wrong_transaction_id(self):
        txid = b"0123456789ab"
        data = self.response(txid, [
            (self.nat.ATTR_XOR_MAPPED_ADDRESS, self.xor_addr("198.51.100.1", 40000, txid))
        ])
        with self.assertRaises(Exception):
            self.nat.parse_stun_response(data, b"xxxxxxxxxxxx")

    def test_classify_no_nat(self):
        observations = [{
            "remote_ip": "203.0.113.1",
            "remote_port": 3478,
            "mapped_ip": "8.8.8.8",
            "mapped_port": 45000,
        }]
        result = self.nat.classify_nat(
            observations,
            local_ip="8.8.8.8",
            local_port=45000,
            filtering_behavior="UNKNOWN",
        )
        self.assertEqual(result["type"], "NO_NAT")

    def test_classify_endpoint_independent_mapping(self):
        observations = [
            {"remote_ip": "203.0.113.1", "remote_port": 3478, "mapped_ip": "198.51.100.8", "mapped_port": 50000},
            {"remote_ip": "203.0.113.1", "remote_port": 53, "mapped_ip": "198.51.100.8", "mapped_port": 50000},
        ]
        result = self.nat.classify_nat(observations, local_ip="192.168.1.10", local_port=41000)
        self.assertEqual(result["type"], "ENDPOINT_INDEPENDENT_MAPPING")
        self.assertEqual(result["mapping_behavior"], "ENDPOINT_INDEPENDENT")
        self.assertFalse(result["port_preservation"])

    def test_classify_symmetric_like_mapping(self):
        observations = [
            {"remote_ip": "203.0.113.1", "remote_port": 3478, "mapped_ip": "198.51.100.8", "mapped_port": 50000},
            {"remote_ip": "203.0.113.1", "remote_port": 53, "mapped_ip": "198.51.100.8", "mapped_port": 50001},
        ]
        result = self.nat.classify_nat(observations, local_ip="192.168.1.10", local_port=41000)
        self.assertEqual(result["type"], "SYMMETRIC_LIKE_MAPPING")
        self.assertEqual(result["mapping_behavior"], "DESTINATION_DEPENDENT")

    def test_single_destination_does_not_overclaim_nat_type(self):
        observations = [
            {"remote_ip": "203.0.113.1", "remote_port": 3478, "mapped_ip": "198.51.100.8", "mapped_port": 50000},
        ]
        result = self.nat.classify_nat(observations, local_ip="192.168.1.10", local_port=41000)
        self.assertEqual(result["type"], "UNKNOWN")
        self.assertEqual(result["reason"], "single_stun_destination")

    def test_cgnat_high_confidence_rfc6598(self):
        result = self.nat.classify_cgnat(
            "198.51.100.8",
            {"available": True, "ip": "100.64.12.3"},
        )
        self.assertEqual(result["status"], "YES")
        self.assertEqual(result["confidence"], "HIGH")

    def test_cgnat_likely_with_private_router_wan_and_public_stun(self):
        result = self.nat.classify_cgnat(
            "8.8.8.8",
            {"available": True, "ip": "10.10.20.30"},
        )
        self.assertEqual(result["status"], "LIKELY")
        self.assertEqual(result["confidence"], "MEDIUM")

    def test_cgnat_no_evidence_when_router_and_stun_match(self):
        result = self.nat.classify_cgnat(
            "8.8.8.8",
            {"available": True, "ip": "8.8.8.8"},
        )
        self.assertEqual(result["status"], "NO_EVIDENCE")
        self.assertEqual(result["confidence"], "HIGH")

    def test_upnp_probe_is_read_only_status_command(self):
        completed = subprocess.CompletedProcess(
            ["upnpc", "-s"],
            0,
            "ExternalIPAddress = 8.8.8.8\n",
            "",
        )
        with patch.object(self.nat.subprocess, "run", return_value=completed) as run:
            result = self.nat.upnp_external_ipv4()
        self.assertTrue(result["available"])
        self.assertEqual(result["ip"], "8.8.8.8")
        args = run.call_args.args[0]
        self.assertEqual(args, ["upnpc", "-s"])
        self.assertNotIn("-a", args)
        self.assertNotIn("-d", args)

    def test_discover_nat_never_claims_wireguard_port_reachability(self):
        def probe(servers, timeout):
            return {
                "local_udp_port": 42000,
                "observations": [
                    {
                        "server": "stun.cloudflare.com:3478",
                        "remote_ip": "203.0.113.1",
                        "remote_port": 3478,
                        "mapped_ip": "8.8.8.8",
                        "mapped_port": 51000,
                    },
                    {
                        "server": "stun.cloudflare.com:53",
                        "remote_ip": "203.0.113.1",
                        "remote_port": 53,
                        "mapped_ip": "8.8.8.8",
                        "mapped_port": 51000,
                    },
                ],
                "errors": [],
                "filtering_behavior": "UNKNOWN",
                "filtering_reason": "server_rfc5780_not_observed",
            }

        report = self.nat.discover_nat(
            ["stun.cloudflare.com:3478", "stun.cloudflare.com:53"],
            probe=probe,
            local_ipv4_getter=lambda: "192.168.1.2",
            ipv6_getter=lambda: ["2001:4860:4860::8888"],
            upnp_getter=lambda: {"available": True, "ip": "8.8.8.8", "global": True},
        )
        self.assertEqual(report["schema"], "ge360-nat-discovery/v1")
        self.assertEqual(report["nat"]["type"], "ENDPOINT_INDEPENDENT_MAPPING")
        self.assertEqual(report["cgnat"]["status"], "NO_EVIDENCE")
        self.assertTrue(report["public_endpoint_observation"]["global_ipv6_available"])
        self.assertFalse(report["public_endpoint_observation"]["wireguard_port_inferred"])
        self.assertFalse(report["phase19_traversal_attempted"])
        self.assertFalse(report["port_mapping_changed"])

    def test_global_ipv6_parser_only_keeps_global(self):
        payload = json.dumps([
            {
                "addr_info": [
                    {"family": "inet6", "local": "2001:4860:4860::8888"},
                    {"family": "inet6", "local": "fe80::1"},
                    {"family": "inet", "local": "192.0.2.1"},
                ]
            }
        ])
        completed = subprocess.CompletedProcess(["ip"], 0, payload, "")
        with patch.object(self.nat.subprocess, "run", return_value=completed):
            result = self.nat.global_ipv6_addresses()
        self.assertEqual(result, ["2001:4860:4860::8888"])


if __name__ == "__main__":
    unittest.main()
