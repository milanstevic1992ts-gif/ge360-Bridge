package com.ge360.bridge

import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class EnrollmentClient(
    private val connectTimeoutMs: Int = 5000,
    private val readTimeoutMs: Int = 8000
) {
    fun enroll(invitation: PairingInvitation, clientPublicKey: String): EnrollmentResult {
        require(clientPublicKey.isNotBlank()) { "Public key client mancante" }

        val expectedFingerprint = invitation.tlsCertSha256.lowercase()
        val trustManager = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain.isNullOrEmpty()) throw CertificateException("Certificato server mancante")
                val digest = MessageDigest.getInstance("SHA-256").digest(chain[0].encoded)
                val actual = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
                if (actual != expectedFingerprint) throw CertificateException("TLS certificate pin mismatch")
            }
        }

        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
        val connection = URL(invitation.enrollmentUrl).openConnection() as HttpsURLConnection
        connection.sslSocketFactory = context.socketFactory
        // Identity is the exact SHA-256 certificate pin carried by the QR.
        connection.hostnameVerifier = HostnameVerifier { _, _ -> true }
        connection.connectTimeout = connectTimeoutMs
        connection.readTimeout = readTimeoutMs
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("Accept", "application/json")

        val body = JSONObject()
            .put("enrollment_id", invitation.enrollmentId)
            .put("token", invitation.token)
            .put("public_key", clientPublicKey)
            .toString()
            .toByteArray(Charsets.UTF_8)

        connection.outputStream.use { it.write(body) }
        val code = connection.responseCode
        val input = if (code in 200..299) connection.inputStream else connection.errorStream
        val text = input?.bufferedReader()?.use { it.readText() }.orEmpty()
        require(code in 200..299) { "Enrollment HTTP $code" }

        val root = JSONObject(text)
        require(root.optBoolean("ok", false)) { root.optString("error", "Enrollment fallito") }
        return parseResult(root.getJSONObject("result"), invitation)
    }

    private fun parseResult(result: JSONObject, invitation: PairingInvitation): EnrollmentResult {
        val wg = result.getJSONObject("wireguard")
        return EnrollmentResult(
            deviceId = result.getString("device_id"),
            device = result.getString("device"),
            vpnIp = result.getString("vpn_ip"),
            presharedKey = result.getString("preshared_key"),
            deviceToken = result.getString("device_token"),
            bridgeIp = result.optString("bridge_ip", "10.88.0.1"),
            healthUrl = result.optString("health_url", "http://10.88.0.1:8788/v1/status"),
            launcherUrl = result.optString("launcher_url", "http://10.88.0.1:8788/hub"),
            serverPublicKey = wg.getString("server_public_key"),
            endpoint = wg.getString("endpoint"),
            allowedIps = wg.optString("allowed_ips", "10.88.0.1/32"),
            persistentKeepalive = wg.optInt("persistent_keepalive", 25),
            runtimeSync = result.optBoolean("runtime_sync", false),
            resources = parseResources(result.optJSONArray("resources") ?: JSONArray()),
            controlUrl = URL(invitation.enrollmentUrl).let { "${it.protocol}://${it.authority}" },
            tlsCertSha256 = invitation.tlsCertSha256
        )
    }

    private fun parseResources(items: JSONArray): List<BridgeResource> =
        (0 until items.length()).map { index ->
            val item = items.getJSONObject(index)
            BridgeResource(
                name = item.getString("name"),
                icon = item.optString("icon", "server"),
                description = item.optString("description", ""),
                protocol = item.optString("protocol", "tcp"),
                bridgePort = item.optInt("bridge_port", 0),
                url = item.optString("url", ""),
                launchable = item.optString("protocol", "tcp") in setOf("http", "https"),
                healthState = null
            )
        }
}
