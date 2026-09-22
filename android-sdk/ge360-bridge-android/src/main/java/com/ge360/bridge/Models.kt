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
    val resources: List<BridgeResource>
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
    val persistentKeepalive: Int
) {
    fun asText(): String = """
        [Interface]
        PrivateKey = $privateKey
        Address = $address/32

        [Peer]
        PublicKey = $serverPublicKey
        PresharedKey = $presharedKey
        Endpoint = $endpoint
        AllowedIPs = $allowedIps
        PersistentKeepalive = $persistentKeepalive
    """.trimIndent()

    override fun toString(): String = "WireGuardConfig(privateKey=<redacted>, address=$address, endpoint=$endpoint)"
}

data class ProvisionedBridge(
    val enrollment: EnrollmentResult,
    val wireGuardConfig: WireGuardConfig
) {
    override fun toString(): String = "ProvisionedBridge(enrollment=$enrollment, wireGuardConfig=$wireGuardConfig)"
}

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}

data class SdkDiagnostics(
    val bridgeReachable: Boolean,
    val statusSchema: String?,
    val resourcesVisible: Int,
    val unhealthyResources: List<String>,
    val error: String?
)
