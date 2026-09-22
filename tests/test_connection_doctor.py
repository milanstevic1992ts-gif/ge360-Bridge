import unittest

from ge360_bridge.doctor import classify, validate_public_endpoint


class ConnectionDoctorTests(unittest.TestCase):
    def resource(self):
        return {
            "name":"rilievi",
            "bridge_port":9888,
            "target_host":"127.0.0.1",
            "target_port":9888,
            "protocol":"http",
        }

    def bridge(self, **overrides):
        base={
            "bridge_service_active":True,
            "wg0_present":True,
            "bridge_port":9888,
            "bridge_port_listening":True,
            "port_conflict":False,
            "listeners":["LISTEN 0 100 10.88.0.1:9888 0.0.0.0:*"],
            "public_endpoint":"203.0.113.10:51820",
            "public_endpoint_valid":True,
            "public_endpoint_error":None,
        }
        base.update(overrides)
        return base

    def device(self, **overrides):
        base={
            "requested":False,
            "found":None,
            "active":None,
            "allowed":None,
            "handshake_age_seconds":None,
            "vpn_up":None,
        }
        base.update(overrides)
        return base

    def diagnostics(self, **checks):
        base={
            "target_tcp":{"ok":True,"host":"127.0.0.1","port":9888,"error":None},
            "api":{"ok":True,"status_code":200,"error":None},
            "pdf":{"ok":False,"skipped":True,"error":"pdf_path_non_fornito"},
        }
        base.update(checks)
        return {"schema":"ge360-bridge-diagnostics/v1","checks":base}

    def health(self, state="ONLINE", error=None):
        return {"state":state,"error":error}

    def category(self, *, bridge=None, device=None, diagnostics=None, health=None):
        result=classify(
            self.resource(),
            diagnostics or self.diagnostics(),
            health or self.health(),
            bridge=bridge or self.bridge(),
            device=device or self.device(),
        )
        return result

    def test_ok(self):
        self.assertEqual(self.category()["category"],"OK")

    def test_bridge_down(self):
        r=self.category(bridge=self.bridge(bridge_service_active=False))
        self.assertEqual(r["category"],"BRIDGE_DOWN")

    def test_port_conflict(self):
        r=self.category(bridge=self.bridge(port_conflict=True,bridge_port_listening=False))
        self.assertEqual(r["category"],"PORT_CONFLICT")

    def test_endpoint_invalid(self):
        r=self.category(bridge=self.bridge(public_endpoint_valid=False,public_endpoint="CHANGE_ME:51820"))
        self.assertEqual(r["category"],"ENDPOINT_INVALID")

    def test_device_not_authorized(self):
        r=self.category(device=self.device(requested=True,found=True,active=False,allowed=False,vpn_up=False))
        self.assertEqual(r["category"],"DEVICE_NOT_AUTHORIZED")

    def test_service_not_allowed(self):
        r=self.category(device=self.device(requested=True,found=True,active=True,allowed=False,vpn_up=True,name="telefono"))
        self.assertEqual(r["category"],"SERVICE_NOT_ALLOWED")

    def test_vpn_down(self):
        r=self.category(device=self.device(requested=True,found=True,active=True,allowed=True,vpn_up=False,name="telefono"))
        self.assertEqual(r["category"],"VPN_DOWN")

    def test_timeout(self):
        d=self.diagnostics(api={"ok":False,"status_code":None,"error":"timeout"})
        r=self.category(diagnostics=d,health=self.health("TIMEOUT","http_timeout"))
        self.assertEqual(r["category"],"TIMEOUT")

    def test_backend_down(self):
        d=self.diagnostics(target_tcp={"ok":False,"host":"127.0.0.1","port":9888,"error":"ConnectionRefusedError"})
        r=self.category(diagnostics=d,health=self.health("OFFLINE","tcp_unreachable"))
        self.assertEqual(r["category"],"BACKEND_DOWN")

    def test_pdf_url_invalid(self):
        d=self.diagnostics(pdf={
            "ok":False,"skipped":False,"request":"/wrong.pdf","status_code":200,
            "content_type":"text/html","pdf_magic":False,"error":"not_a_pdf"
        })
        r=self.category(diagnostics=d)
        self.assertEqual(r["category"],"PDF_URL_INVALID")

    def test_http_error(self):
        d=self.diagnostics(api={"ok":False,"status_code":500,"content_type":"application/json","error":"http_500"})
        r=self.category(diagnostics=d,health=self.health("BAD_RESPONSE","http_500"))
        self.assertEqual(r["category"],"HTTP_ERROR")

    def test_precedence_bridge_before_backend(self):
        d=self.diagnostics(target_tcp={"ok":False,"host":"127.0.0.1","port":9888,"error":"ConnectionRefusedError"})
        r=self.category(bridge=self.bridge(bridge_service_active=False),diagnostics=d)
        self.assertEqual(r["category"],"BRIDGE_DOWN")
        cats=[x["category"] for x in r["findings"]]
        self.assertIn("BACKEND_DOWN",cats)

    def test_endpoint_validation(self):
        self.assertEqual(validate_public_endpoint("203.0.113.10:51820"),(True,None))
        self.assertEqual(validate_public_endpoint("[2001:db8::1]:51820"),(True,None))
        self.assertFalse(validate_public_endpoint("CHANGE_ME:51820")[0])
        self.assertFalse(validate_public_endpoint("bad")[0])


if __name__=="__main__":
    unittest.main()
