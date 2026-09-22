package com.ge360.bridge

import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Phase19TraversalTest {
    private val cookie = 0x2112A442

    @Test fun stunBindingRequestHasRfc5389Header() {
        val txid = ByteArray(12) { it.toByte() }
        val request = StunCandidateDiscoverer.buildBindingRequest(txid)
        assertEquals(20, request.size)
        val buffer = ByteBuffer.wrap(request).order(ByteOrder.BIG_ENDIAN)
        assertEquals(0x0001, buffer.short.toInt() and 0xffff)
        assertEquals(0, buffer.short.toInt() and 0xffff)
        assertEquals(cookie, buffer.int)
        val actual = ByteArray(12).also { buffer.get(it) }
        assertArrayEquals(txid, actual)
    }

    @Test fun parsesXorMappedCandidateAndKeepsLocalPort() {
        val txid = ByteArray(12) { (it + 1).toByte() }
        val ip = InetAddress.getByName("1.1.1.1").address
        val mappedPort = 55000
        val cookieBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(cookie).array()
        val xorIp = ByteArray(4) { index -> (ip[index].toInt() xor cookieBytes[index].toInt()).toByte() }
        val value = ByteBuffer.allocate(8)
            .order(ByteOrder.BIG_ENDIAN)
            .put(0)
            .put(1)
            .putShort((mappedPort xor (cookie ushr 16)).toShort())
            .put(xorIp)
            .array()
        val attr = ByteBuffer.allocate(12)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0020.toShort())
            .putShort(8)
            .put(value)
            .array()
        val response = ByteBuffer.allocate(20 + attr.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101.toShort())
            .putShort(attr.size.toShort())
            .putInt(cookie)
            .put(txid)
            .put(attr)
            .array()

        val candidate = StunCandidateDiscoverer.parseResponse(response, txid, 51821)
        assertEquals("1.1.1.1", candidate.ip)
        assertEquals(mappedPort, candidate.port)
        assertEquals(51821, candidate.localPort)
        assertEquals("1.1.1.1:55000", candidate.endpoint)
    }

    @Test fun rejectsStunResponseWithWrongTransactionId() {
        val txid = ByteArray(12) { it.toByte() }
        val response = ByteBuffer.allocate(20)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101.toShort())
            .putShort(0)
            .putInt(cookie)
            .put(txid)
            .array()
        assertThrows(IllegalArgumentException::class.java) {
            StunCandidateDiscoverer.parseResponse(response, ByteArray(12) { 9 }, 51821)
        }
    }

    @Test fun wireGuardConfigCarriesStableTraversalListenPort() {
        val client = KeyPair()
        val server = KeyPair()
        val psk = KeyPair().privateKey.toBase64()
        val config = WireGuardConfig(
            privateKey = client.privateKey.toBase64(),
            address = "10.88.0.2",
            serverPublicKey = server.publicKey.toBase64(),
            presharedKey = psk,
            endpoint = "8.8.8.8:51820",
            allowedIps = "10.88.0.1/32",
            persistentKeepalive = 25,
            listenPort = 51821
        )
        val text = config.asText()
        assertTrue(text.contains("ListenPort = 51821"))
        assertTrue(text.contains("AllowedIPs = 10.88.0.1/32"))
        val parsed = Config.parse(ByteArrayInputStream(text.toByteArray()))
        assertTrue(parsed.toWgQuickString().contains("ListenPort = 51821"))
        assertTrue(parsed.toWgQuickString().contains("AllowedIPs = 10.88.0.1/32"))
    }

    @Test fun secureCodecPersistsTraversalListenPort() {
        val config = WireGuardConfig(
            privateKey = "private-secret",
            address = "10.88.0.2",
            serverPublicKey = "server-public",
            presharedKey = "psk-secret",
            endpoint = "8.8.8.8:51820",
            allowedIps = "10.88.0.1/32",
            persistentKeepalive = 25,
            listenPort = 51823
        )
        val decoded = TunnelConfigCodec.decode(TunnelConfigCodec.encode(config))
        assertEquals(51823, decoded.listenPort)
        assertFalse(decoded.toString().contains("private-secret"))
        assertFalse(decoded.toString().contains("psk-secret"))
    }

    @Test fun traversalModelsDoNotContainDeviceToken() {
        val candidate = TraversalCandidate("1.1.1.1", 55000, 51821)
        val plan = TraversalPlan(
            sessionId = "p2p_test",
            status = "PREPARED",
            recommendedEndpoint = "8.8.8.8:51820",
            fallbackEndpoint = "8.8.8.8:51820",
            expiresAt = 1234,
            clientCandidate = candidate,
            serverCandidates = listOf("8.8.8.8:51820")
        )
        assertEquals("1.1.1.1:55000", plan.clientCandidate.endpoint)
        assertFalse(plan.toString().contains("device-token"))
    }
    @Test fun connectPreferP2PFallsBackToDirectWhenPreparationFails() {
        class FakeVpn : VpnController {
            var started: WireGuardConfig? = null
            override fun state(): ConnectionState = if (started == null) ConnectionState.DISCONNECTED else ConnectionState.CONNECTED
            override fun start(config: WireGuardConfig) { started = config }
            override fun stop() { started = null }
        }
        val vpn = FakeVpn()
        val session = BridgeSession(
            keyProvider = object : WireGuardKeyProvider {
                override fun generate(): WireGuardKeyMaterial = WireGuardKeyMaterial("private", "public")
            },
            vpnController = vpn
        )
        val enrollment = EnrollmentResult(
            deviceId = "dev_test",
            device = "telefono",
            vpnIp = "10.88.0.2",
            presharedKey = "psk",
            deviceToken = "token",
            bridgeIp = "10.88.0.1",
            healthUrl = "http://10.88.0.1:8788/v1/status",
            launcherUrl = "http://10.88.0.1:8788/hub",
            serverPublicKey = "server",
            endpoint = "8.8.8.8:51820",
            allowedIps = "10.88.0.1/32",
            persistentKeepalive = 25,
            runtimeSync = true,
            resources = emptyList(),
            controlUrl = "https://8.8.8.8:8790",
            tlsCertSha256 = "0".repeat(64)
        )
        val direct = WireGuardConfig(
            privateKey = "private",
            address = "10.88.0.2",
            serverPublicKey = "server",
            presharedKey = "psk",
            endpoint = "8.8.8.8:51820",
            allowedIps = "10.88.0.1/32",
            persistentKeepalive = 25
        )
        val provisioned = ProvisionedBridge(enrollment, direct)
        val failing = object : TraversalClient() {
            override fun prepare(enrollment: EnrollmentResult): TraversalPlan {
                throw IllegalStateException("no control path")
            }
        }

        val plan = session.connectPreferP2P(provisioned, failing)
        assertNull(plan)
        assertEquals("8.8.8.8:51820", vpn.started?.endpoint)
        assertEquals(0, vpn.started?.listenPort)
    }

}
