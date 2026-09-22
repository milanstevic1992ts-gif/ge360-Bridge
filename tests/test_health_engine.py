import json
import socket
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

from ge360_bridge.health import check_resource, clear_cache, health_summary


class HealthHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/ok":
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/plain":
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/unauthorized":
            body = json.dumps({"error": "unauthorized"}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/bad":
            body = json.dumps({"ok": False}).encode()
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/invalid-json":
            body = b"{bad"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/empty":
            body = b""
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HealthEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        clear_cache()

    def resource(self, path="/ok", protocol="http"):
        return {
            "name": "test",
            "protocol": protocol,
            "target_host": "127.0.0.1",
            "target_port": self.port,
            "health_url": path,
            "timeout_seconds": 1.0,
            "enabled": True,
        }

    def test_tcp_resource_online(self):
        result = check_resource(self.resource("", "tcp"), use_cache=False)
        self.assertEqual(result["state"], "ONLINE")
        self.assertTrue(result["checks"]["tcp"]["ok"])
        self.assertFalse(result["checks"]["http"]["performed"])

    def test_http_json_online(self):
        result = check_resource(self.resource("/ok"), use_cache=False)
        self.assertEqual(result["state"], "ONLINE")
        self.assertEqual(result["checks"]["http"]["status_code"], 200)
        self.assertTrue(result["checks"]["json"]["ok"])
        self.assertIsNotNone(result["latency_ms"])

    def test_plain_text_is_degraded_not_offline(self):
        result = check_resource(self.resource("/plain"), use_cache=False)
        self.assertEqual(result["state"], "DEGRADED")
        self.assertEqual(result["error"], "non_json_health_response")
        self.assertTrue(result["checks"]["tcp"]["ok"])

    def test_http_without_health_url_is_degraded(self):
        result = check_resource(self.resource("", "http"), use_cache=False)
        self.assertEqual(result["state"], "DEGRADED")
        self.assertEqual(result["error"], "health_url_not_configured")

    def test_unauthorized_state(self):
        result = check_resource(self.resource("/unauthorized"), use_cache=False)
        self.assertEqual(result["state"], "UNAUTHORIZED")
        self.assertEqual(result["checks"]["http"]["status_code"], 401)

    def test_non_success_status_is_bad_response(self):
        result = check_resource(self.resource("/bad"), use_cache=False)
        self.assertEqual(result["state"], "BAD_RESPONSE")
        self.assertEqual(result["checks"]["http"]["status_code"], 503)

    def test_invalid_json_is_bad_response(self):
        result = check_resource(self.resource("/invalid-json"), use_cache=False)
        self.assertEqual(result["state"], "BAD_RESPONSE")
        self.assertEqual(result["error"], "invalid_json")

    def test_empty_health_body_is_degraded(self):
        result = check_resource(self.resource("/empty"), use_cache=False)
        self.assertEqual(result["state"], "DEGRADED")
        self.assertEqual(result["error"], "empty_health_body")

    def test_tcp_timeout_state(self):
        with patch("ge360_bridge.health.socket.create_connection", side_effect=socket.timeout):
            result = check_resource(self.resource(), use_cache=False)
        self.assertEqual(result["state"], "TIMEOUT")
        self.assertEqual(result["error"], "tcp_timeout")

    def test_tcp_offline_state(self):
        with patch("ge360_bridge.health.socket.create_connection", side_effect=ConnectionRefusedError):
            result = check_resource(self.resource(), use_cache=False)
        self.assertEqual(result["state"], "OFFLINE")
        self.assertEqual(result["error"], "tcp_unreachable")

    def test_tls_verification_failure_is_bad_response(self):
        fake_socket = MagicMock()
        fake_connection = MagicMock()
        fake_connection.request.side_effect = ssl.SSLCertVerificationError(1, "certificate verify failed")
        with patch("ge360_bridge.health.socket.create_connection", return_value=fake_socket), \
             patch("ge360_bridge.health.http.client.HTTPSConnection", return_value=fake_connection):
            result = check_resource(
                {
                    **self.resource("/ok", "https"),
                    "name": "tls-test",
                },
                use_cache=False,
            )
        self.assertEqual(result["state"], "BAD_RESPONSE")
        self.assertEqual(result["error"], "tls_certificate_invalid")
        self.assertTrue(result["checks"]["tls"]["performed"])
        self.assertFalse(result["checks"]["tls"]["ok"])

    def test_health_summary_counts_states(self):
        summary = health_summary([
            {"state": "ONLINE"},
            {"state": "ONLINE"},
            {"state": "DEGRADED"},
            {"state": "TIMEOUT"},
        ])
        self.assertEqual(summary["ONLINE"], 2)
        self.assertEqual(summary["DEGRADED"], 1)
        self.assertEqual(summary["TIMEOUT"], 1)
        self.assertEqual(summary["TOTAL"], 4)


if __name__ == "__main__":
    unittest.main()
