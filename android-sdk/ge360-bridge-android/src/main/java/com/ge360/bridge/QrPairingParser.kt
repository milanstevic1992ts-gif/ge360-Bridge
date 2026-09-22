package com.ge360.bridge

import org.json.JSONObject
import java.net.URI

object QrPairingParser {
    private val fingerprint = Regex("^[0-9a-fA-F]{64}$")

    fun parse(raw: String): PairingInvitation {
        val root = JSONObject(raw)
        require(root.getString("schema") == "ge360-bridge-pairing/v2") { "Schema pairing non supportato" }

        val enrollmentUrl = root.getString("enrollment_url")
        val uri = URI(enrollmentUrl)
        require(uri.scheme.equals("https", ignoreCase = true)) { "Enrollment URL deve essere HTTPS" }

        val cert = root.getString("tls_cert_sha256").lowercase()
        require(fingerprint.matches(cert)) { "Fingerprint TLS non valido" }

        val token = root.getString("token")
        require(token.length >= 32) { "Token pairing non valido" }

        val wg = root.getJSONObject("wireguard")
        val serverPublicKey = wg.getString("server_public_key")
        require(serverPublicKey.isNotBlank()) { "Public key server mancante" }
        val endpoint = wg.getString("endpoint")
        require(endpoint.isNotBlank()) { "Endpoint WireGuard mancante" }

        return PairingInvitation(
            enrollmentId = root.getString("enrollment_id"),
            device = root.getString("device"),
            enrollmentUrl = enrollmentUrl,
            token = token,
            expiresAt = root.getLong("expires_at"),
            tlsCertSha256 = cert,
            wireGuard = WireGuardServer(
                publicKey = serverPublicKey,
                endpoint = endpoint,
                allowedIps = wg.optString("allowed_ips", "10.88.0.1/32"),
                persistentKeepalive = wg.optInt("persistent_keepalive", 25)
            )
        )
    }
}
