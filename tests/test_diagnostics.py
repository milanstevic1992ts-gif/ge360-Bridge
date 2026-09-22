import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from ge360_bridge.diagnostics import (
    DiagnosticError,
    api_test,
    diagnose_resource,
    dns_lookup,
    pdf_test,
    ping_host,
    tcp_test,
    traceroute_host,
)


class DiagnosticHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/api":
            body = json.dumps({"ok": True, "value": 1}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/pdf":
            body = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
        elif self.path == "/fake-pdf":
            body = b"<html>not pdf</html>"
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DiagnosticHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def resource(self):
        return {
            "name": "rilievi",
            "protocol": "http",
            "bridge_port": 19888,
            "target_host": "127.0.0.1",
            "target_port": self.port,
            "health_url": "/api",
            "timeout_seconds": 1.0,
            "enabled": True,
        }

    def test_dns_localhost(self):
        result = dns_lookup("localhost")
        self.assertTrue(result["ok"])
        self.assertTrue(result["addresses"])

    def test_tcp_target(self):
        result = tcp_test("127.0.0.1", self.port)
        self.assertTrue(result["ok"])
        self.assertIsNotNone(result["latency_ms"])

    def test_api_json(self):
        result = api_test(self.resource(), "/api")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status_code"], 200)
        self.assertTrue(result["json_valid"])

    def test_api_rejects_url_outside_resource(self):
        result = api_test(self.resource(), "http://127.0.0.1:9/api")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "url_fuori_resource")

    def test_pdf_requires_real_pdf_magic(self):
        result = pdf_test(self.resource(), "/pdf")
        self.assertTrue(result["ok"])
        self.assertTrue(result["pdf_magic"])
        self.assertEqual(result["content_type"], "application/pdf")

    def test_fake_pdf_fails_even_with_pdf_content_type(self):
        result = pdf_test(self.resource(), "/fake-pdf")
        self.assertFalse(result["ok"])
        self.assertFalse(result["pdf_magic"])
        self.assertEqual(result["error"], "not_a_pdf")

    def test_ping_parsing(self):
        class Proc:
            returncode = 0
            stdout = (
                "2 packets transmitted, 2 received, 0% packet loss, time 1000ms\n"
                "rtt min/avg/max/mdev = 0.050/0.075/0.100/0.010 ms\n"
            )
            stderr = ""
        with patch("ge360_bridge.diagnostics._run", return_value=Proc()):
            result = ping_host("127.0.0.1")
        self.assertTrue(result["ok"])
        self.assertEqual(result["packets_received"], 2)
        self.assertEqual(result["packet_loss_percent"], 0.0)
        self.assertEqual(result["rtt_avg_ms"], 0.075)

    def test_traceroute_parsing(self):
        class Proc:
            returncode = 0
            stdout = "traceroute to 127.0.0.1\n1  127.0.0.1  0.030 ms\n"
            stderr = ""
        with patch("ge360_bridge.diagnostics._run", return_value=Proc()):
            result = traceroute_host("127.0.0.1")
        self.assertTrue(result["ok"])
        self.assertEqual(result["hops"], ["1  127.0.0.1  0.030 ms"])

    def test_diagnose_resource_composes_phase6_checks(self):
        with patch("ge360_bridge.diagnostics.ping_host", side_effect=[
            {"check":"ping","host":"10.88.0.1","ok":True},
            {"check":"ping","host":"127.0.0.1","ok":True},
        ]), patch(
            "ge360_bridge.diagnostics.traceroute_host",
            return_value={"check":"traceroute","host":"127.0.0.1","ok":True,"hops":["1 127.0.0.1"]},
        ):
            report = diagnose_resource(
                self.resource(),
                api_path="/api",
                pdf_path="/pdf",
                include_traceroute=True,
            )
        self.assertEqual(report["schema"], "ge360-bridge-diagnostics/v1")
        self.assertTrue(report["checks"]["bridge_ping"]["ok"])
        self.assertTrue(report["checks"]["backend_ping"]["ok"])
        self.assertTrue(report["checks"]["target_tcp"]["ok"])
        self.assertTrue(report["checks"]["api"]["ok"])
        self.assertTrue(report["checks"]["pdf"]["ok"])
        self.assertTrue(report["checks"]["dns"]["ok"])
        self.assertTrue(report["checks"]["traceroute"]["ok"])
        self.assertEqual(report["summary"]["failed"], 0)


if __name__ == "__main__":
    unittest.main()
