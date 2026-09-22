package com.ge360.bridge

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

open class RelayFallbackClient(
    private val connectTimeoutMs: Int = 5_000,
    private val readTimeoutMs: Int = 8_000,
    private val pollAttempts: Int = 20,
    private val pollDelayMs: Long = 500
) {
    init {
        require(pollAttempts >= 1)
        require(pollDelayMs >= 0)
    }

    open fun requestAndWait(
        config: WireGuardConfig,
        reason: RelayFallbackReason
    ): RelayPlan {
        validateConfig(config)
        val first = postPinned(
            config,
            "/v1/device/request",
            JSONObject()
                .put("device_id", config.deviceId)
                .put("device_token", config.deviceToken)
                .put("reason", reason.wireValue)
        )
        val initial = first.getJSONObject("result")
        val sessionId = initial.getString("session_id")
        val clientEndpoint = initial.getString("client_endpoint")
        val bridgeEndpoint = initial.getString("bridge_endpoint")
        var status = initial.optString("status", "WAITING_BRIDGE")

        repeat(pollAttempts) {
            if (status == "ACTIVE") {
                return RelayPlan(
                    sessionId = sessionId,
                    status = status,
                    clientEndpoint = clientEndpoint,
                    bridgeEndpoint = bridgeEndpoint,
                    fallbackReason = reason
                )
            }
            if (status in setOf("FAILED", "ERROR", "EXPIRED")) {
                throw IllegalStateException("Relay fallback $status")
            }
            if (pollDelayMs > 0) Thread.sleep(pollDelayMs)
            val root = postPinned(
                config,
                "/v1/device/status",
                JSONObject()
                    .put("device_id", config.deviceId)
                    .put("device_token", config.deviceToken)
                    .put("session_id", sessionId)
            )
            status = root.getJSONObject("result").optString("status", "UNKNOWN")
        }
        throw IllegalStateException("Relay activation timeout")
    }

    internal fun validateConfig(config: WireGuardConfig) {
        require(config.deviceId.isNotBlank()) { "deviceId relay mancante" }
        require(config.deviceToken.isNotBlank()) { "deviceToken relay mancante" }
        require(config.relayUrl.startsWith("https://")) { "relayUrl deve essere HTTPS" }
        require(config.relayCertSha256.matches(Regex("[0-9a-fA-F]{64}"))) {
            "relay certificate pin non valido"
        }
    }

    private fun postPinned(
        config: WireGuardConfig,
        path: String,
        body: JSONObject
    ): JSONObject {
        val expectedFingerprint = config.relayCertSha256.lowercase()
        val trustManager = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain.isNullOrEmpty()) throw CertificateException("Certificato relay mancante")
                val digest = MessageDigest.getInstance("SHA-256").digest(chain[0].encoded)
                val actual = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
                if (actual != expectedFingerprint) throw CertificateException("Relay TLS certificate pin mismatch")
            }
        }
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())

        val connection = URL(config.relayUrl.trimEnd('/') + path).openConnection() as HttpsURLConnection
        connection.sslSocketFactory = context.socketFactory
        connection.hostnameVerifier = HostnameVerifier { _, _ -> true }
        connection.connectTimeout = connectTimeoutMs
        connection.readTimeout = readTimeoutMs
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("Accept", "application/json")
        val bytes = body.toString().toByteArray(Charsets.UTF_8)
        connection.outputStream.use { it.write(bytes) }
        val code = connection.responseCode
        val input = if (code in 200..299) connection.inputStream else connection.errorStream
        val text = input?.bufferedReader()?.use { it.readText() }.orEmpty()
        require(code in 200..299) { "Relay HTTP $code" }
        val root = JSONObject(text)
        require(root.optBoolean("ok", false)) { root.optString("error", "Relay fallback fallito") }
        return root
    }
}
