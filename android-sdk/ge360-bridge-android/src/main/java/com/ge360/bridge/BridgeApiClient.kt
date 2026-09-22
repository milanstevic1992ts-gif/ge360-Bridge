package com.ge360.bridge

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class BridgeApiClient(
    private val bridgeBaseUrl: String = "http://10.88.0.1:8788",
    private val timeoutMs: Int = 4000
) {
    fun status(): JSONObject = getJson("/v1/status")

    fun resources(): List<BridgeResource> {
        val root = getJson("/v1/resources")
        val items = root.optJSONArray("resources") ?: JSONArray()
        return (0 until items.length()).map { index ->
            val item = items.getJSONObject(index)
            BridgeResource(
                name = item.getString("name"),
                icon = item.optString("icon", "server"),
                description = item.optString("description", ""),
                protocol = item.optString("protocol", "tcp"),
                bridgePort = item.optInt("bridge_port", 0),
                url = item.optString("url", ""),
                launchable = item.optBoolean("launchable", false),
                healthState = item.optJSONObject("health")?.optString("state")
            )
        }
    }

    fun diagnostics(): SdkDiagnostics {
        return try {
            val status = status()
            val resources = resources()
            SdkDiagnostics(
                bridgeReachable = true,
                statusSchema = status.optString("schema").ifBlank { null },
                resourcesVisible = resources.size,
                unhealthyResources = resources.filter {
                    it.healthState != null && it.healthState != "ONLINE"
                }.map { it.name },
                error = null
            )
        } catch (exc: Exception) {
            SdkDiagnostics(
                bridgeReachable = false,
                statusSchema = null,
                resourcesVisible = 0,
                unhealthyResources = emptyList(),
                error = exc.javaClass.simpleName
            )
        }
    }

    private fun getJson(path: String): JSONObject {
        val connection = URL(bridgeBaseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection
        connection.connectTimeout = timeoutMs
        connection.readTimeout = timeoutMs
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/json")
        val code = connection.responseCode
        val text = (if (code in 200..299) connection.inputStream else connection.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        require(code in 200..299) { "Bridge HTTP $code" }
        return JSONObject(text)
    }
}
