package com.ge360.bridge

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class StoredTunnel(
    val config: WireGuardConfig,
    val desiredConnected: Boolean
) {
    override fun toString(): String =
        "StoredTunnel(config=<redacted>, desiredConnected=$desiredConnected)"
}

class SecureTunnelStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun save(config: WireGuardConfig, desiredConnected: Boolean) {
        val payload = TunnelConfigCodec.encode(config)
        val encrypted = encrypt(payload.toByteArray(Charsets.UTF_8))
        check(
            prefs.edit()
                .putString(KEY_BLOB, encrypted)
                .putBoolean(KEY_DESIRED, desiredConnected)
                .commit()
        ) { "Impossibile salvare il tunnel GE360" }
    }

    fun setDesiredConnected(desiredConnected: Boolean) {
        prefs.edit().putBoolean(KEY_DESIRED, desiredConnected).apply()
    }

    fun load(): StoredTunnel? {
        val blob = prefs.getString(KEY_BLOB, null) ?: return null
        return try {
            val text = decrypt(blob).toString(Charsets.UTF_8)
            StoredTunnel(
                config = TunnelConfigCodec.decode(text),
                desiredConnected = prefs.getBoolean(KEY_DESIRED, false)
            )
        } catch (_: Exception) {
            clear()
            null
        }
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    private fun encrypt(plain: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val cipherText = cipher.doFinal(plain)
        val envelope = JSONObject()
            .put("v", 1)
            .put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(cipherText, Base64.NO_WRAP))
        return envelope.toString()
    }

    private fun decrypt(envelopeText: String): ByteArray {
        val envelope = JSONObject(envelopeText)
        require(envelope.getInt("v") == 1) { "Versione store non supportata" }
        val iv = Base64.decode(envelope.getString("iv"), Base64.NO_WRAP)
        val cipherText = Base64.decode(envelope.getString("ciphertext"), Base64.NO_WRAP)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        return cipher.doFinal(cipherText)
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val PREFS = "ge360_bridge_secure_tunnel"
        private const val KEY_BLOB = "tunnel_blob"
        private const val KEY_DESIRED = "desired_connected"
        private const val KEY_ALIAS = "ge360.bridge.tunnel.aes.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}


internal object TunnelConfigCodec {
    fun encode(config: WireGuardConfig): String =
        JSONObject()
            .put("private_key", config.privateKey)
            .put("address", config.address)
            .put("server_public_key", config.serverPublicKey)
            .put("preshared_key", config.presharedKey)
            .put("endpoint", config.endpoint)
            .put("allowed_ips", config.allowedIps)
            .put("persistent_keepalive", config.persistentKeepalive)
            .put("listen_port", config.listenPort)
            .put("device_id", config.deviceId)
            .put("device_token", config.deviceToken)
            .put("relay_url", config.relayUrl)
            .put("relay_cert_sha256", config.relayCertSha256)
            .toString()

    fun decode(text: String): WireGuardConfig {
        val root = JSONObject(text)
        return WireGuardConfig(
            privateKey = root.getString("private_key"),
            address = root.getString("address"),
            serverPublicKey = root.getString("server_public_key"),
            presharedKey = root.getString("preshared_key"),
            endpoint = root.getString("endpoint"),
            allowedIps = root.getString("allowed_ips"),
            persistentKeepalive = root.getInt("persistent_keepalive"),
            listenPort = root.optInt("listen_port", 0),
            deviceId = root.optString("device_id", ""),
            deviceToken = root.optString("device_token", ""),
            relayUrl = root.optString("relay_url", ""),
            relayCertSha256 = root.optString("relay_cert_sha256", "")
        )
    }
}
