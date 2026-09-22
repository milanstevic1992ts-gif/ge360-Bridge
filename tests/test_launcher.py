import unittest

from ge360_bridge.launcher import launcher_payload, multi_server_catalog_payload, render_hub, resources_for_launcher


class LauncherTests(unittest.TestCase):
    def device(self):
        return {
            "device_id":"dev_1","name":"telefono","vpn_ip":"10.88.0.2",
            "enabled":True,"expires_at":None,
        }

    def resources(self):
        return [
            {
                "name":"rilievi","icon":"ruler","description":"Rilievi","protocol":"http",
                "bridge_port":9888,"target_host":"127.0.0.1","target_port":9888,
                "allowed_devices":["telefono"],"denied_devices":[],"enabled":True,
            },
            {
                "name":"firefly","icon":"money","description":"Firefly","protocol":"http",
                "bridge_port":8794,"target_host":"127.0.0.1","target_port":8794,
                "allowed_devices":[],"denied_devices":[],"enabled":True,
            },
            {
                "name":"rawtcp","icon":"server","description":"TCP","protocol":"tcp",
                "bridge_port":9000,"target_host":"127.0.0.1","target_port":9000,
                "allowed_devices":["telefono"],"denied_devices":[],"enabled":True,
            },
        ]

    def test_only_authorized_resources_are_exposed(self):
        health=[
            {"name":"rilievi","state":"ONLINE"},
            {"name":"rawtcp","state":"ONLINE"},
        ]
        out=resources_for_launcher(
            self.device(),resources=self.resources(),groups=[],health_results=health
        )
        self.assertEqual([x["name"] for x in out],["rilievi","rawtcp"])
        self.assertNotIn("firefly",[x["name"] for x in out])

    def test_http_is_launchable_tcp_is_not(self):
        out=resources_for_launcher(
            self.device(),resources=self.resources(),groups=[],
            health_results=[{"name":"rilievi","state":"ONLINE"},{"name":"rawtcp","state":"ONLINE"}],
        )
        by={x["name"]:x for x in out}
        self.assertTrue(by["rilievi"]["launchable"])
        self.assertEqual(by["rilievi"]["url"],"http://10.88.0.1:9888")
        self.assertFalse(by["rawtcp"]["launchable"])
        self.assertEqual(by["rawtcp"]["url"],"tcp://10.88.0.1:9000")

    def test_group_authorization_is_respected(self):
        resources=self.resources()
        resources[0]["allowed_devices"]=[]
        groups=[{
            "name":"staff","device_ids":["dev_1"],"allowed_services":["rilievi"],
            "allowed_resources":["rilievi"],"enabled":True,
        }]
        out=resources_for_launcher(
            self.device(),resources=resources,groups=groups,
            health_results=[{"name":"rilievi","state":"ONLINE"}],
        )
        self.assertIn("rilievi",[x["name"] for x in out])

    def test_render_does_not_leak_device_secrets(self):
        device={**self.device(),"token":"secret-token","preshared_key":"secret-psk"}
        resources=[{
            "name":"rilievi","icon":"ruler","description":"Rilievi","protocol":"http",
            "bridge_port":9888,"url":"http://10.88.0.1:9888","launchable":True,
            "health":{"state":"ONLINE"},
        }]
        html=render_hub(device,resources)
        self.assertIn("GE360 HUB",html)
        self.assertIn("rilievi",html)
        self.assertNotIn("secret-token",html)
        self.assertNotIn("secret-psk",html)

    def test_multi_server_catalog_preserves_remote_resources_but_filters_local_acl(self):
        local = [{
            "name":"rilievi","icon":"ruler","description":"Rilievi","protocol":"http",
            "bridge_port":9888,"url":"http://10.88.0.1:9888","launchable":True,
            "health":{"state":"ONLINE"},
        }]
        catalog = {
            "control_server_id":"srv_local",
            "servers":[{"server_id":"srv_local","name":"local"},{"server_id":"srv_remote","name":"remote"}],
            "resources":[
                {"resource_id":"srv_local:rilievi","server_id":"srv_local","name":"rilievi","local":True},
                {"resource_id":"srv_local:secret","server_id":"srv_local","name":"secret","local":True},
                {"resource_id":"srv_remote:firefly","server_id":"srv_remote","name":"firefly","local":False},
            ],
        }
        payload=multi_server_catalog_payload(self.device(),local,catalog)
        ids={x["resource_id"] for x in payload["resources"]}
        self.assertIn("srv_local:rilievi",ids)
        self.assertNotIn("srv_local:secret",ids)
        self.assertIn("srv_remote:firefly",ids)
        self.assertFalse(payload["remote_resource_proxy"])

    def test_payload_schema(self):
        payload=launcher_payload(self.device(),[])
        self.assertEqual(payload["schema"],"ge360-resource-launcher/v1")
        self.assertEqual(payload["device_id"],"dev_1")


if __name__=="__main__":
    unittest.main()
