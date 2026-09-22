package com.ge360.bridge

import org.junit.Assert.*
import org.junit.Test

class WireGuardConfigTest {
    @Test fun rendersExpectedRestrictedRoute() {
        val config=WireGuardConfig(
            privateKey="private-secret",
            address="10.88.0.2",
            serverPublicKey="server",
            presharedKey="psk-secret",
            endpoint="203.0.113.10:51820",
            allowedIps="10.88.0.1/32",
            persistentKeepalive=25
        )
        val text=config.asText()
        assertTrue(text.contains("AllowedIPs = 10.88.0.1/32"))
        assertTrue(text.contains("Address = 10.88.0.2/32"))
        assertFalse(config.toString().contains("private-secret"))
        assertFalse(config.toString().contains("psk-secret"))
    }
}
