package com.ge360.bridge

import org.junit.Assert.*
import org.junit.Test

class QrPairingParserTest {
    private fun payload(fingerprint: String = "a".repeat(64)) = """
        {
          "schema":"ge360-bridge-pairing/v2",
          "enrollment_id":"enr_1",
          "device":"telefono",
          "enrollment_url":"https://203.0.113.10:8790/v2/enroll",
          "token":"1234567890123456789012345678901234567890",
          "expires_at":4102444800,
          "tls_cert_sha256":"$fingerprint",
          "wireguard":{
            "server_public_key":"server-key",
            "endpoint":"203.0.113.10:51820",
            "allowed_ips":"10.88.0.1/32",
            "persistent_keepalive":25
          }
        }
    """.trimIndent()

    @Test fun parsesV2Payload() {
        val p=QrPairingParser.parse(payload())
        assertEquals("enr_1",p.enrollmentId)
        assertEquals("telefono",p.device)
        assertEquals("10.88.0.1/32",p.wireGuard.allowedIps)
        assertFalse(p.toString().contains(p.token))
    }

    @Test(expected=IllegalArgumentException::class)
    fun rejectsBadFingerprint() {
        QrPairingParser.parse(payload("bad"))
    }

    @Test(expected=IllegalArgumentException::class)
    fun rejectsNonHttpsEnrollment() {
        QrPairingParser.parse(payload().replace("https://","http://"))
    }
}
