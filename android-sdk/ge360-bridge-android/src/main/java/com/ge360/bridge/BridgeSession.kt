package com.ge360.bridge

interface PairingCodeSource {
    fun acquirePairingCode(): String
}

interface WireGuardKeyProvider {
    fun generate(): WireGuardKeyMaterial
}

interface VpnController {
    fun state(): ConnectionState
    fun start(config: WireGuardConfig)
    fun stop()
}

class BridgeSession(
    private val keyProvider: WireGuardKeyProvider,
    private val vpnController: VpnController,
    private val enrollmentClient: EnrollmentClient = EnrollmentClient(),
    private val apiClient: BridgeApiClient = BridgeApiClient()
) {
    fun provision(rawQrPayload: String): ProvisionedBridge {
        val invitation = QrPairingParser.parse(rawQrPayload)
        require(invitation.expiresAt * 1000L > System.currentTimeMillis()) { "Pairing scaduto" }
        val keys = keyProvider.generate()
        val enrollment = enrollmentClient.enroll(invitation, keys.publicKey)
        val config = WireGuardConfig(
            privateKey = keys.privateKey,
            address = enrollment.vpnIp,
            serverPublicKey = enrollment.serverPublicKey,
            presharedKey = enrollment.presharedKey,
            endpoint = enrollment.endpoint,
            allowedIps = enrollment.allowedIps,
            persistentKeepalive = enrollment.persistentKeepalive
        )
        return ProvisionedBridge(enrollment, config)
    }

    fun provision(source: PairingCodeSource): ProvisionedBridge =
        provision(source.acquirePairingCode())

    fun connect(provisioned: ProvisionedBridge) {
        vpnController.start(provisioned.wireGuardConfig)
    }

    fun connectPreferP2P(
        provisioned: ProvisionedBridge,
        traversalClient: TraversalClient = TraversalClient()
    ): TraversalPlan? {
        val plan = try {
            traversalClient.prepare(provisioned.enrollment)
        } catch (_: Exception) {
            vpnController.start(provisioned.wireGuardConfig)
            return null
        }
        val p2pConfig = provisioned.wireGuardConfig.copy(
            endpoint = plan.recommendedEndpoint,
            listenPort = plan.clientCandidate.localPort
        )
        vpnController.start(p2pConfig)
        return plan
    }

    fun traversalStatus(
        provisioned: ProvisionedBridge,
        plan: TraversalPlan,
        traversalClient: TraversalClient = TraversalClient()
    ): TraversalStatus = traversalClient.status(provisioned.enrollment, plan.sessionId)

    fun fallbackToDirect(provisioned: ProvisionedBridge) {
        vpnController.start(provisioned.wireGuardConfig)
    }

    fun disconnect() = vpnController.stop()
    fun connectionState(): ConnectionState = vpnController.state()
    fun status(): JSONObjectFacade = JSONObjectFacade(apiClient.status().toString())
    fun resources(): List<BridgeResource> = apiClient.resources()
    fun diagnostics(): SdkDiagnostics = apiClient.diagnostics()
}

/**
 * Keeps org.json out of the public API surface.
 */
data class JSONObjectFacade(val json: String)
