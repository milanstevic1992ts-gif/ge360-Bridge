package com.ge360.bridge

import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class StunCandidateDiscoverer(
    private val serverHost: String = "stun.cloudflare.com",
    private val serverPort: Int = 3478,
    private val timeoutMs: Int = 1_500,
    private val preferredPorts: IntRange = 51821..51830
) {
    fun discover(): TraversalCandidate {
        require(serverPort in 1..65535) { "Porta STUN non valida" }
        var lastError: Exception? = null
        for (localPort in preferredPorts) {
            try {
                DatagramSocket(null).use { socket ->
                    socket.reuseAddress = true
                    socket.soTimeout = timeoutMs
                    socket.bind(InetSocketAddress("0.0.0.0", localPort))
                    val transactionId = ByteArray(12).also { SecureRandom().nextBytes(it) }
                    val request = buildBindingRequest(transactionId)
                    val remote = InetSocketAddress(InetAddress.getByName(serverHost), serverPort)
                    socket.send(DatagramPacket(request, request.size, remote))
                    val buffer = ByteArray(2048)
                    val response = DatagramPacket(buffer, buffer.size)
                    socket.receive(response)
                    return parseResponse(
                        response.data.copyOf(response.length),
                        transactionId,
                        localPort
                    )
                }
            } catch (exc: Exception) {
                lastError = exc
            }
        }
        throw IllegalStateException("Nessuna porta locale STUN disponibile", lastError)
    }

    companion object {
        private const val MAGIC_COOKIE = 0x2112A442
        private const val BINDING_REQUEST = 0x0001
        private const val BINDING_SUCCESS = 0x0101
        private const val ATTR_MAPPED_ADDRESS = 0x0001
        private const val ATTR_XOR_MAPPED_ADDRESS = 0x0020

        internal fun buildBindingRequest(transactionId: ByteArray): ByteArray {
            require(transactionId.size == 12)
            return ByteBuffer.allocate(20)
                .order(ByteOrder.BIG_ENDIAN)
                .putShort(BINDING_REQUEST.toShort())
                .putShort(0)
                .putInt(MAGIC_COOKIE)
                .put(transactionId)
                .array()
        }

        internal fun parseResponse(
            data: ByteArray,
            expectedTransactionId: ByteArray,
            localPort: Int
        ): TraversalCandidate {
            require(data.size >= 20) { "Risposta STUN troppo corta" }
            val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val type = buffer.short.toInt() and 0xffff
            val length = buffer.short.toInt() and 0xffff
            val cookie = buffer.int
            val transactionId = ByteArray(12).also { buffer.get(it) }
            require(type == BINDING_SUCCESS) { "Risposta STUN non-success" }
            require(cookie == MAGIC_COOKIE) { "Magic cookie STUN non valida" }
            require(transactionId.contentEquals(expectedTransactionId)) { "Transaction ID STUN non corrisponde" }
            require(length == data.size - 20) { "Lunghezza risposta STUN non valida" }

            var offset = 20
            var mapped: Pair<String, Int>? = null
            while (offset < data.size) {
                require(offset + 4 <= data.size) { "Attributo STUN troncato" }
                val attrBuffer = ByteBuffer.wrap(data, offset, 4).order(ByteOrder.BIG_ENDIAN)
                val attrType = attrBuffer.short.toInt() and 0xffff
                val attrLength = attrBuffer.short.toInt() and 0xffff
                val start = offset + 4
                val stop = start + attrLength
                require(stop <= data.size) { "Attributo STUN non valido" }
                val value = data.copyOfRange(start, stop)
                if (attrType == ATTR_XOR_MAPPED_ADDRESS || attrType == ATTR_MAPPED_ADDRESS) {
                    mapped = parseAddress(
                        value,
                        xor = attrType == ATTR_XOR_MAPPED_ADDRESS
                    )
                    if (attrType == ATTR_XOR_MAPPED_ADDRESS) break
                }
                offset = start + ((attrLength + 3) / 4) * 4
            }
            val result = requireNotNull(mapped) { "MAPPED-ADDRESS STUN mancante" }
            return TraversalCandidate(
                ip = result.first,
                port = result.second,
                localPort = localPort,
                source = "stun"
            )
        }

        private fun parseAddress(value: ByteArray, xor: Boolean): Pair<String, Int> {
            require(value.size >= 8) { "Attributo address STUN troppo corto" }
            val buffer = ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN)
            buffer.get()
            val family = buffer.get().toInt() and 0xff
            var port = buffer.short.toInt() and 0xffff
            require(family == 0x01) { "Solo IPv4 STUN supportato dal client Fase 19" }
            val address = ByteArray(4).also { buffer.get(it) }
            if (xor) {
                port = port xor (MAGIC_COOKIE ushr 16)
                val cookie = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(MAGIC_COOKIE).array()
                for (i in address.indices) address[i] = (address[i].toInt() xor cookie[i].toInt()).toByte()
            }
            return InetAddress.getByAddress(address).hostAddress to port
        }
    }
}

class TraversalApiClient(
    private val connectTimeoutMs: Int = 5_000,
    private val readTimeoutMs: Int = 8_000
) {
    fun prepare(enrollment: EnrollmentResult, candidate: TraversalCandidate): TraversalPlan {
        require(enrollment.controlUrl.startsWith("https://")) { "Control URL P2P non HTTPS" }
        require(enrollment.tlsCertSha256.length == 64) { "TLS pin P2P mancante" }
        val body = JSONObject()
            .put("device_id", enrollment.deviceId)
            .put("device_token", enrollment.deviceToken)
            .put(
                "candidate",
                JSONObject()
                    .put("ip", candidate.ip)
                    .put("port", candidate.port)
                    .put("local_port", candidate.localPort)
                    .put("source", candidate.source)
            )
        val root = postPinned(enrollment, "/v3/traversal/prepare", body)
        return parsePlan(root.getJSONObject("result"), candidate)
    }

    fun status(enrollment: EnrollmentResult, sessionId: String): TraversalStatus {
        val body = JSONObject()
            .put("device_id", enrollment.deviceId)
            .put("device_token", enrollment.deviceToken)
            .put("session_id", sessionId)
        val root = postPinned(enrollment, "/v3/traversal/status", body)
        val result = root.getJSONObject("result")
        return TraversalStatus(
            sessionId = result.getString("session_id"),
            status = result.optString("status", "UNKNOWN"),
            attempts = result.optInt("attempts", 0),
            latestHandshake = result.optLong("latest_handshake", 0L),
            error = result.optString("error").ifBlank { null }
        )
    }

    private fun parsePlan(result: JSONObject, candidate: TraversalCandidate): TraversalPlan {
        val server = result.optJSONArray("server_candidates") ?: JSONArray()
        return TraversalPlan(
            sessionId = result.getString("session_id"),
            status = result.optString("status", "PREPARED"),
            recommendedEndpoint = result.getString("recommended_endpoint"),
            fallbackEndpoint = result.optString("fallback_endpoint", ""),
            expiresAt = result.optLong("expires_at", 0L),
            clientCandidate = candidate,
            serverCandidates = (0 until server.length()).map { index ->
                server.getJSONObject(index).getString("endpoint")
            }
        )
    }

    private fun postPinned(
        enrollment: EnrollmentResult,
        path: String,
        body: JSONObject
    ): JSONObject {
        val expectedFingerprint = enrollment.tlsCertSha256.lowercase()
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

        val connection = URL(enrollment.controlUrl.trimEnd('/') + path).openConnection() as HttpsURLConnection
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
        require(code in 200..299) { "Traversal HTTP $code" }
        val root = JSONObject(text)
        require(root.optBoolean("ok", false)) { root.optString("error", "Traversal fallito") }
        return root
    }
}

open class TraversalClient(
    private val discoverer: StunCandidateDiscoverer = StunCandidateDiscoverer(),
    private val api: TraversalApiClient = TraversalApiClient()
) {
    open fun prepare(enrollment: EnrollmentResult): TraversalPlan {
        val candidate = discoverer.discover()
        return api.prepare(enrollment, candidate)
    }

    open fun status(enrollment: EnrollmentResult, sessionId: String): TraversalStatus =
        api.status(enrollment, sessionId)
}
