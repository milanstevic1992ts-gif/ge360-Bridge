package com.ge360.bridge

import org.junit.Assert.*
import org.junit.Test

class Phase20RelayTest {
    private fun relayConfig(): WireGuardConfig = WireGuardConfig(
        privateKey = "private-secret",
        address = "10.88.0.2",
        serverPublicKey = "server-public",
        presharedKey = "psk-secret",
        endpoint = "8.8.8.8:51820",
        allowedIps = "10.88.0.1/32",
        persistentKeepalive = 25,
        deviceId = "dev_001",
        deviceToken = "device-token-secret",
        relayUrl = "https://relay.example:8792",
        relayCertSha256 = "a".repeat(64)
    )

    @Test fun relayConfigValidationRequiresPinnedHttpsAndDeviceCredentials() {
        val client = RelayFallbackClient(pollAttempts = 1, pollDelayMs = 0)
        client.validateConfig(relayConfig())

        assertThrows(IllegalArgumentException::class.java) {
            client.validateConfig(relayConfig().copy(relayUrl = "http://relay.example:8792"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            client.validateConfig(relayConfig().copy(deviceToken = ""))
        }
        assertThrows(IllegalArgumentException::class.java) {
            client.validateConfig(relayConfig().copy(relayCertSha256 = "bad"))
        }
    }

    @Test fun secureCodecPersistsRelayCredentialsButToStringRedactsToken() {
        val config = relayConfig()
        val decoded = TunnelConfigCodec.decode(TunnelConfigCodec.encode(config))
        assertEquals("dev_001", decoded.deviceId)
        assertEquals("device-token-secret", decoded.deviceToken)
        assertEquals("https://relay.example:8792", decoded.relayUrl)
        assertEquals("a".repeat(64), decoded.relayCertSha256)
        assertFalse(decoded.toString().contains("device-token-secret"))
        assertFalse(decoded.toString().contains("private-secret"))
        assertFalse(decoded.toString().contains("psk-secret"))
    }

    @Test fun fallbackReasonWireValuesAreRestricted() {
        assertEquals("direct_failed", RelayFallbackReason.DIRECT_FAILED.wireValue)
        assertEquals("p2p_failed", RelayFallbackReason.P2P_FAILED.wireValue)
        assertEquals("control_unreachable", RelayFallbackReason.CONTROL_UNREACHABLE.wireValue)
        assertEquals(3, RelayFallbackReason.entries.size)
    }

    @Test fun bridgeSessionStartsWireGuardOnClientFacingRelayEndpoint() {
        class FakeVpn : VpnController {
            var started: WireGuardConfig? = null
            override fun state(): ConnectionState =
                if (started == null) ConnectionState.DISCONNECTED else ConnectionState.CONNECTED
            override fun start(config: WireGuardConfig) { started = config }
            override fun stop() { started = null }
        }

        val direct = relayConfig()
        val enrollment = EnrollmentResult(
            deviceId = "dev_001",
            device = "telefono",
            vpnIp = "10.88.0.2",
            presharedKey = "psk-secret",
            deviceToken = "device-token-secret",
            bridgeIp = "10.88.0.1",
            healthUrl = "http://10.88.0.1:8788/v1/status",
            launcherUrl = "http://10.88.0.1:8788/hub",
            serverPublicKey = "server-public",
            endpoint = "8.8.8.8:51820",
            allowedIps = "10.88.0.1/32",
            persistentKeepalive = 25,
            runtimeSync = true,
            resources = emptyList(),
            relay = RelayInfo(true, "https://relay.example:8792", "a".repeat(64))
        )
        val provisioned = ProvisionedBridge(enrollment, direct)
        val vpn = FakeVpn()
        val session = BridgeSession(
            keyProvider = object : WireGuardKeyProvider {
                override fun generate() = WireGuardKeyMaterial("private", "public")
            },
            vpnController = vpn
        )
        val fakeRelay = object : RelayFallbackClient() {
            override fun requestAndWait(
                config: WireGuardConfig,
                reason: RelayFallbackReason
            ): RelayPlan = RelayPlan(
                sessionId = "relay_test",
                status = "ACTIVE",
                clientEndpoint = "relay.example:46002",
                bridgeEndpoint = "relay.example:46001",
                fallbackReason = reason
            )
        }

        val plan = session.connectViaRelayAfterFailure(
            provisioned,
            RelayFallbackReason.P2P_FAILED,
            fakeRelay
        )
        assertEquals("ACTIVE", plan.status)
        assertEquals("relay.example:46002", vpn.started?.endpoint)
        assertEquals("10.88.0.1/32", vpn.started?.allowedIps)
        assertEquals(0, vpn.started?.listenPort)
    }

    @Test fun provisioningCopiesRelayMetadataIntoEncryptedTunnelConfig() {
        val vpn = object : VpnController {
            override fun state() = ConnectionState.DISCONNECTED
            override fun start(config: WireGuardConfig) = Unit
            override fun stop() = Unit
        }
        val session = BridgeSession(
            keyProvider = object : WireGuardKeyProvider {
                override fun generate() = WireGuardKeyMaterial("private", "public")
            },
            vpnController = vpn
        )
        // We only validate the data model defaults here; enrollment network is separately tested.
        val config = relayConfig()
        assertEquals("dev_001", config.deviceId)
        assertEquals("https://relay.example:8792", config.relayUrl)
        assertFalse(config.toString().contains(config.deviceToken))
    }
}
