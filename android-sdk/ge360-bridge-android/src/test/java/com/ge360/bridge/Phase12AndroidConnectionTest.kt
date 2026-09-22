package com.ge360.bridge

import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream

class Phase12AndroidConnectionTest {
    @Test fun generatesRealWireGuardKeyPairAndRedactsPrivateKey() {
        val material = AndroidWireGuardKeyProvider().generate()
        assertEquals(44, material.privateKey.length)
        assertEquals(44, material.publicKey.length)
        assertNotEquals(material.privateKey, material.publicKey)
        assertFalse(material.toString().contains(material.privateKey))
    }

    @Test fun reconnectBackoffIsBounded() {
        val policy = ReconnectPolicy(maxAttempts = 6, initialDelayMs = 1_000, maxDelayMs = 30_000)
        assertEquals(1_000, policy.delayForAttempt(1))
        assertEquals(2_000, policy.delayForAttempt(2))
        assertEquals(4_000, policy.delayForAttempt(3))
        assertEquals(16_000, policy.delayForAttempt(5))
        assertEquals(30_000, policy.delayForAttempt(6))
        assertEquals(30_000, policy.delayForAttempt(20))
    }

    @Test fun connectionStatesCoverPermissionAndReconnect() {
        val states = ConnectionState.entries.toSet()
        assertTrue(states.contains(ConnectionState.DISCONNECTED))
        assertTrue(states.contains(ConnectionState.WAITING_PERMISSION))
        assertTrue(states.contains(ConnectionState.CONNECTING))
        assertTrue(states.contains(ConnectionState.CONNECTED))
        assertTrue(states.contains(ConnectionState.RECONNECTING))
        assertTrue(states.contains(ConnectionState.ERROR))
    }

    @Test fun officialWireGuardParserAcceptsRestrictedConfig() {
        val client = KeyPair()
        val server = KeyPair()
        val psk = KeyPair().privateKey.toBase64()
        val config = WireGuardConfig(
            privateKey = client.privateKey.toBase64(),
            address = "10.88.0.2",
            serverPublicKey = server.publicKey.toBase64(),
            presharedKey = psk,
            endpoint = "203.0.113.10:51820",
            allowedIps = "10.88.0.1/32",
            persistentKeepalive = 25
        )

        val parsed = Config.parse(ByteArrayInputStream(config.asText().toByteArray()))
        assertEquals(1, parsed.peers.size)
        assertTrue(parsed.toWgQuickString().contains("AllowedIPs = 10.88.0.1/32"))
    }

    @Test fun encryptedStoreCodecRoundTripsSensitiveConfigWithoutLoggingIt() {
        val config = WireGuardConfig(
            privateKey = "private-secret",
            address = "10.88.0.2",
            serverPublicKey = "server-public",
            presharedKey = "psk-secret",
            endpoint = "203.0.113.10:51820",
            allowedIps = "10.88.0.1/32",
            persistentKeepalive = 25
        )
        val decoded = TunnelConfigCodec.decode(TunnelConfigCodec.encode(config))
        assertEquals(config, decoded)
        assertFalse(config.toString().contains("private-secret"))
        assertFalse(config.toString().contains("psk-secret"))
    }
}
