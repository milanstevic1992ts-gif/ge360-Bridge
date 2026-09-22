package com.ge360.bridge

data class WireGuardServer(
    val publicKey: String,
    val endpoint: String,
    val allowedIps: String,
    val persistentKeepalive: Int
)

class PairingInvitation(
    val enrollmentId: String,
    val device: String,
    val enrollmentUrl: String,
    val token: String,
    val expiresAt: Long,
    val tlsCertSha256: String,
    val wireGuard: WireGuardServer
) {
    override fun toString(): String =
        "PairingInvitation(enrollmentId=$enrollmentId, device=$device, enrollmentUrl=$enrollmentUrl, token=<redacted>, expiresAt=$expiresAt, tlsCertSha256=$tlsCertSha256)"
}

data class RelayInfo(
    val enabled: Boolean = false,
    val url: String = "",
    val tlsCertSha256: String = ""
)

data class BridgeResource(
    val name: String,
    val icon: String,
    val description: String,
    val protocol: String,
    val bridgePort: Int,
    val url: String,
    val launchable: Boolean,
    val healthState: String?
)

class EnrollmentResult(
    val deviceId: String,
    val device: String,
    val vpnIp: String,
    val presharedKey: String,
    val deviceToken: String,
    val bridgeIp: String,
    val healthUrl: String,
    val launcherUrl: String,
    val serverPublicKey: String,
    val endpoint: String,
    val allowedIps: String,
    val persistentKeepalive: Int,
    val runtimeSync: Boolean,
    val resources: List<BridgeResource>,
    val controlUrl: String = "",
    val tlsCertSha256: String = "",
    val relay: RelayInfo = RelayInfo()
) {
    override fun toString(): String =
        "EnrollmentResult(deviceId=$deviceId, device=$device, vpnIp=$vpnIp, presharedKey=<redacted>, deviceToken=<redacted>, bridgeIp=$bridgeIp, runtimeSync=$runtimeSync)"
}

data class WireGuardKeyMaterial(
    val privateKey: String,
    val publicKey: String
) {
    override fun toString(): String = "WireGuardKeyMaterial(privateKey=<redacted>, publicKey=$publicKey)"
}

data class WireGuardConfig(
    val privateKey: String,
    val address: String,
    val serverPublicKey: String,
    val presharedKey: String,
    val endpoint: String,
    val allowedIps: String,
    val persistentKeepalive: Int,
    val listenPort: Int = 0,
    val deviceId: String = "",
    val deviceToken: String = "",
    val relayUrl: String = "",
    val relayCertSha256: String = ""
) {
    fun asText(): String {
        val listenLine = if (listenPort in 1..65535) "ListenPort = $listenPort\n" else ""
        return """
        [Interface]
        PrivateKey = $privateKey
        Address = $address/32
        $listenLine
        [Peer]
        PublicKey = $serverPublicKey
        PresharedKey = $presharedKey
        Endpoint = $endpoint
        AllowedIPs = $allowedIps
        PersistentKeepalive = $persistentKeepalive
    """.trimIndent()
    }

    override fun toString(): String = "WireGuardConfig(privateKey=<redacted>, address=$address, endpoint=$endpoint, listenPort=$listenPort, deviceId=$deviceId, deviceToken=<redacted>)"
}

enum class RelayFallbackReason(val wireValue: String) {
    DIRECT_FAILED("direct_failed"),
    P2P_FAILED("p2p_failed"),
    CONTROL_UNREACHABLE("control_unreachable")
}

data class RelayPlan(
    val sessionId: String,
    val status: String,
    val clientEndpoint: String,
    val bridgeEndpoint: String,
    val fallbackReason: RelayFallbackReason
)

data class TraversalCandidate(
    val ip: String,
    val port: Int,
    val localPort: Int,
    val source: String = "stun"
) {
    val endpoint: String get() = if (ip.contains(":")) "[$ip]:$port" else "$ip:$port"
}

data class TraversalPlan(
    val sessionId: String,
    val status: String,
    val recommendedEndpoint: String,
    val fallbackEndpoint: String,
    val expiresAt: Long,
    val clientCandidate: TraversalCandidate,
    val serverCandidates: List<String>
)

data class TraversalStatus(
    val sessionId: String,
    val status: String,
    val attempts: Int,
    val latestHandshake: Long,
    val error: String?
)

data class ProvisionedBridge(
    val enrollment: EnrollmentResult,
    val wireGuardConfig: WireGuardConfig
) {
    override fun toString(): String = "ProvisionedBridge(enrollment=$enrollment, wireGuardConfig=$wireGuardConfig)"
}

enum class ConnectionState {
    DISCONNECTED,
    WAITING_PERMISSION,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    ERROR
}

data class SdkDiagnostics(
    val bridgeReachable: Boolean,
    val statusSchema: String?,
    val resourcesVisible: Int,
    val unhealthyResources: List<String>,
    val error: String?
)
