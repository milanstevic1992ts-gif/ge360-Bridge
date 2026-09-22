import importlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class SelfHealingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["GE360_BRIDGE_STATE_DIR"] = self.tmp.name

        import ge360_bridge.core as core
        self.core = importlib.reload(core)

        import ge360_bridge.audit as audit
        self.audit = importlib.reload(audit)

        import ge360_bridge.health as health
        self.health = importlib.reload(health)

        import ge360_bridge.self_healing as self_healing
        self.sh = importlib.reload(self_healing)
        self.state_path = Path(self.tmp.name) / "self_heal_state.json"

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("GE360_BRIDGE_STATE_DIR", None)

    def resource(self, **overrides):
        base = {
            "name": "rilievi",
            "bridge_port": 9888,
            "target_host": "127.0.0.1",
            "target_port": 9888,
            "allowed_devices": [],
            "protocol": "http",
            "health_url": "/healthz",
            "systemd_unit": "ge360-rilievi.service",
            "self_heal_enabled": True,
            "enabled": True,
        }
        base.update(overrides)
        return base

    def test_legacy_resource_defaults_self_heal_off(self):
        legacy = [{
            "name": "rilievi",
            "bridge_port": 9888,
            "target_host": "127.0.0.1",
            "target_port": 9888,
            "allowed_devices": [],
        }]
        self.core._atomic_write(self.core.RESOURCES_FILE, legacy)
        resource = self.core.list_resources()[0]
        self.assertEqual(resource["systemd_unit"], "")
        self.assertFalse(resource["self_heal_enabled"])

    def test_self_heal_requires_safe_systemd_unit(self):
        with self.assertRaises(self.core.BridgeError):
            self.core.register_resource(
                "rilievi",
                9888,
                "127.0.0.1",
                9888,
                [],
                self_heal_enabled=True,
            )
        with self.assertRaises(self.core.BridgeError):
            self.core.validate_systemd_unit("ge360-bridge.service")
        with self.assertRaises(self.core.BridgeError):
            self.core.validate_systemd_unit("../../bad.service")
        self.assertEqual(
            self.core.validate_systemd_unit("ge360-rilievi.service"),
            "ge360-rilievi.service",
        )

    def test_non_restartable_health_state_does_nothing(self):
        calls = []

        def checker(resource, use_cache=False):
            return {"name": resource["name"], "state": "DEGRADED", "latency_ms": 2, "checks": {}}

        def runner(args):
            calls.append(args)
            return subprocess.CompletedProcess(["systemctl", *args], 0, "loaded\n", "")

        result = self.sh.heal_resource(
            self.resource(),
            {},
            now_epoch=1000,
            dry_run=False,
            checker=checker,
            runner=runner,
            sleeper=lambda _: None,
            state_path=self.state_path,
        )
        self.assertEqual(result["result"], "NO_ACTION")
        self.assertEqual(calls, [])

    def test_offline_backend_restarts_then_recovers(self):
        health_states = iter(["OFFLINE", "ONLINE"])
        calls = []

        def checker(resource, use_cache=False):
            state = next(health_states)
            return {"name": resource["name"], "state": state, "latency_ms": 3.2, "checks": {}}

        def runner(args):
            calls.append(args)
            if args[0] == "show":
                return subprocess.CompletedProcess(["systemctl", *args], 0, "loaded\n", "")
            return subprocess.CompletedProcess(["systemctl", *args], 0, "", "")

        result = self.sh.heal_resource(
            self.resource(),
            {},
            now_epoch=1000,
            dry_run=False,
            checker=checker,
            runner=runner,
            sleeper=lambda _: None,
            state_path=self.state_path,
        )
        self.assertEqual(result["result"], "RECOVERED")
        self.assertEqual(result["health_after"], "ONLINE")
        self.assertIn(["restart", "ge360-rilievi.service"], calls)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(state["rilievi"]), 1)
        events = self.audit.list_events(resource="rilievi")
        self.assertTrue(any(x["event"] == "SELF_HEAL_RECOVERED" for x in events))

    def test_failed_restart_counts_against_limit(self):
        def checker(resource, use_cache=False):
            return {"name": resource["name"], "state": "OFFLINE", "latency_ms": None, "checks": {}}

        def runner(args):
            if args[0] == "show":
                return subprocess.CompletedProcess(["systemctl", *args], 0, "loaded\n", "")
            return subprocess.CompletedProcess(["systemctl", *args], 1, "", "restart failed")

        result = self.sh.heal_resource(
            self.resource(),
            {},
            now_epoch=1000,
            dry_run=False,
            checker=checker,
            runner=runner,
            sleeper=lambda _: None,
            state_path=self.state_path,
        )
        self.assertEqual(result["result"], "RESTART_FAILED")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(state["rilievi"]), 1)

    def test_fourth_restart_is_blocked_within_ten_minutes(self):
        self.core.register_resource(
            "rilievi",
            9888,
            "127.0.0.1",
            9888,
            [],
            protocol="http",
            health_url="/healthz",
            systemd_unit="ge360-rilievi.service",
            self_heal_enabled=True,
        )
        restart_calls = []

        def checker(resource, use_cache=False):
            return {"name": resource["name"], "state": "OFFLINE", "latency_ms": None, "error": "down", "checks": {}}

        def runner(args):
            if args[0] == "show":
                return subprocess.CompletedProcess(["systemctl", *args], 0, "loaded\n", "")
            restart_calls.append(args)
            return subprocess.CompletedProcess(["systemctl", *args], 0, "", "")

        results = []
        for now in (1000, 1001, 1002, 1003):
            report = self.sh.run_self_heal(
                "rilievi",
                now_epoch=now,
                checker=checker,
                runner=runner,
                sleeper=lambda _: None,
                state_path=self.state_path,
            )
            results.append(report["results"][0]["result"])

        self.assertEqual(results[:3], ["STILL_UNHEALTHY"] * 3)
        self.assertEqual(results[3], "RATE_LIMITED")
        self.assertEqual(len(restart_calls), 3)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(len(state["rilievi"]), 3)

    def test_attempt_expires_after_window(self):
        self.state_path.write_text(json.dumps({"rilievi": [1000, 1001, 1002]}), encoding="utf-8")
        status = self.sh._prune_state(self.sh._load_state(self.state_path), 1603)
        self.assertEqual(status, {})

    def test_dry_run_never_restarts_or_consumes_attempt(self):
        self.core.register_resource(
            "rilievi",
            9888,
            "127.0.0.1",
            9888,
            [],
            systemd_unit="ge360-rilievi.service",
            self_heal_enabled=True,
        )
        calls = []

        def checker(resource, use_cache=False):
            return {"name": resource["name"], "state": "OFFLINE", "latency_ms": None, "checks": {}}

        def runner(args):
            calls.append(args)
            return subprocess.CompletedProcess(["systemctl", *args], 0, "loaded\n", "")

        report = self.sh.run_self_heal(
            "rilievi",
            dry_run=True,
            now_epoch=1000,
            checker=checker,
            runner=runner,
            sleeper=lambda _: None,
            state_path=self.state_path,
        )
        self.assertEqual(report["results"][0]["result"], "WOULD_RESTART")
        self.assertFalse(any(x and x[0] == "restart" for x in calls))
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state, {})


if __name__ == "__main__":
    unittest.main()
