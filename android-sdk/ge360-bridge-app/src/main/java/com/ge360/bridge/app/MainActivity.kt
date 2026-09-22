package com.ge360.bridge.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.ge360.bridge.AndroidBridgeRuntime
import com.ge360.bridge.BridgeResource
import com.ge360.bridge.ConnectionState
import com.ge360.bridge.ConnectionStateListener
import com.ge360.bridge.Ge360AndroidBridge
import com.ge360.bridge.ProvisionedBridge
import com.ge360.bridge.RelayFallbackReason
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.snackbar.Snackbar
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class MainActivity : AppCompatActivity() {
    private enum class Route(val label: String) {
        RESTORED("Configurazione salvata"),
        DIRECT("Direct WireGuard"),
        P2P("NAT Traversal P2P"),
        RELAY("Relay self-hosted")
    }

    private lateinit var runtime: AndroidBridgeRuntime
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val probeGeneration = AtomicInteger(0)

    private var provisioned: ProvisionedBridge? = null
    private var route = Route.RESTORED
    private var permissionRequestInFlight = false

    private lateinit var root: LinearLayout
    private lateinit var stateText: TextView
    private lateinit var routeText: TextView
    private lateinit var detailsText: TextView
    private lateinit var diagnosticsText: TextView
    private lateinit var catalogText: TextView
    private lateinit var resourcesBox: LinearLayout
    private lateinit var progress: LinearProgressIndicator

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        permissionRequestInFlight = false
        runtime.onVpnPermissionResult(result.resultCode == Activity.RESULT_OK)
        if (result.resultCode != Activity.RESULT_OK) {
            snackbar("Permesso VPN non concesso")
        }
    }

    private val qrScanner = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let(::provisionAndConnect)
    }

    private val stateListener = ConnectionStateListener { state ->
        runOnUiThread {
            renderState(state)
            if (state == ConnectionState.WAITING_PERMISSION) {
                requestVpnPermission()
            }
            if (state == ConnectionState.CONNECTED) {
                scheduleReachabilityProbe()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        runtime = Ge360AndroidBridge.create(this, autoRestore = true)
        runtime.vpnController.addStateListener(stateListener)
        renderState(runtime.session.connectionState())

        if (runtime.session.connectionState() == ConnectionState.CONNECTED) {
            route = Route.RESTORED
            renderRoute()
            refreshBridgeData()
        }
    }

    override fun onDestroy() {
        runtime.vpnController.removeStateListener(stateListener)
        runtime.close()
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun buildUi() {
        val scroll = ScrollView(this)
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(36))
        }
        scroll.addView(root)
        setContentView(scroll)

        root.addView(TextView(this).apply {
            text = "GE360 Bridge"
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
        })
        root.addView(TextView(this).apply {
            text = "Client Android del Universal Bridge"
            textSize = 15f
            alpha = 0.72f
            setPadding(0, dp(2), 0, dp(16))
        })

        val statusCard = card("Connessione")
        stateText = valueText("DISCONNECTED")
        routeText = valueText("Percorso: —")
        detailsText = valueText("Bridge: http://10.88.0.1:8788")
        progress = LinearProgressIndicator(this).apply {
            visibility = View.GONE
            isIndeterminate = true
        }
        statusCard.addView(stateText)
        statusCard.addView(routeText)
        statusCard.addView(detailsText)
        statusCard.addView(progress)

        val pairCard = card("Associazione")
        pairCard.addView(buttonRow(
            button("Scansiona QR") { startQrScan() },
            button("Incolla codice") { showPasteDialog() }
        ))
        pairCard.addView(buttonRow(
            button("Riconnetti") {
                provisioned?.let(::connectSmart)
                    ?: run {
                        route = Route.RESTORED
                        renderRoute()
                        runtime.restore()
                        requestVpnPermission()
                    }
            },
            button("Disconnetti") {
                probeGeneration.incrementAndGet()
                runtime.session.disconnect()
            }
        ))

        val diagCard = card("Diagnostica")
        diagnosticsText = valueText("Premi Aggiorna dopo la connessione.")
        diagCard.addView(diagnosticsText)
        diagCard.addView(buttonRow(
            button("Aggiorna") { refreshBridgeData() },
            button("Dimentica") { confirmForget() }
        ))

        val catalogCard = card("Multi-server")
        catalogText = valueText("Catalogo non ancora letto.")
        catalogCard.addView(catalogText)
        catalogCard.addView(button("Aggiorna catalogo") { refreshCatalog() })

        val resourcesCard = card("Resource autorizzate")
        resourcesBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        resourcesBox.addView(valueText("Nessuna Resource caricata."))
        resourcesCard.addView(resourcesBox)

        root.addView(valueText(
            "Ordine automatico: Direct → P2P → Relay. Il traffico resta limitato a 10.88.0.1/32."
        ).apply {
            alpha = 0.68f
            setPadding(dp(4), dp(10), dp(4), 0)
        })
    }

    private fun card(title: String): LinearLayout {
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(16))
        }
        content.addView(TextView(this).apply {
            text = title
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, dp(10))
        })

        root.addView(MaterialCardView(this).apply {
            radius = dp(18).toFloat()
            cardElevation = dp(1).toFloat()
            setContentPadding(0, 0, 0, 0)
            addView(content)
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            bottomMargin = dp(12)
        })
        return content
    }

    private fun valueText(value: String) = TextView(this).apply {
        text = value
        textSize = 15f
        setLineSpacing(0f, 1.12f)
        setPadding(0, dp(3), 0, dp(3))
    }

    private fun button(label: String, action: () -> Unit) = MaterialButton(this).apply {
        text = label
        isAllCaps = false
        setOnClickListener { action() }
    }

    private fun buttonRow(first: View, second: View): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(first, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dp(5)
            })
            addView(second, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = dp(5)
            })
        }

    private fun startQrScan() {
        val options = ScanOptions()
            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            .setPrompt("Inquadra il QR generato dal GE360 Bridge")
            .setBeepEnabled(false)
            .setOrientationLocked(false)
        qrScanner.launch(options)
    }

    private fun showPasteDialog() {
        val input = EditText(this).apply {
            hint = "Payload QR / pairing v2"
            minLines = 4
            setPadding(dp(18), dp(10), dp(18), dp(10))
        }
        AlertDialog.Builder(this)
            .setTitle("Incolla codice Bridge")
            .setView(input)
            .setNegativeButton("Annulla", null)
            .setPositiveButton("Connetti") { _, _ ->
                val text = input.text?.toString()?.trim().orEmpty()
                if (text.isNotBlank()) provisionAndConnect(text)
            }
            .show()
    }

    private fun provisionAndConnect(raw: String) {
        setBusy(true)
        diagnosticsText.text = "Pairing in corso…"
        worker.execute {
            val result = runCatching { runtime.session.provision(raw) }
            runOnUiThread {
                setBusy(false)
                result.onSuccess {
                    provisioned = it
                    detailsText.text = "Dispositivo: ${it.enrollment.device}\nVPN IP: ${it.enrollment.vpnIp}"
                    connectSmart(it)
                }.onFailure {
                    diagnosticsText.text = "Pairing fallito: ${friendlyError(it)}"
                    snackbar("Impossibile completare il pairing")
                }
            }
        }
    }

    private fun connectSmart(value: ProvisionedBridge) {
        provisioned = value
        route = Route.DIRECT
        renderRoute()
        probeGeneration.incrementAndGet()
        runtime.session.connect(value)
        requestVpnPermission()
    }

    private fun requestVpnPermission() {
        if (permissionRequestInFlight) return
        val intent = runtime.vpnPermissionIntent() ?: return
        permissionRequestInFlight = true
        vpnPermission.launch(intent)
    }

    private fun scheduleReachabilityProbe() {
        val generation = probeGeneration.incrementAndGet()
        main.postDelayed({
            if (generation == probeGeneration.get()) {
                probeReachability(generation)
            }
        }, 2200)
    }

    private fun probeReachability(generation: Int) {
        setBusy(true)
        worker.execute {
            val diagnostics = runtime.session.diagnostics()
            if (generation != probeGeneration.get()) return@execute
            if (diagnostics.bridgeReachable) {
                runOnUiThread {
                    setBusy(false)
                    diagnosticsText.text =
                        "Bridge ONLINE · Resource visibili: ${diagnostics.resourcesVisible}" +
                        (diagnostics.unhealthyResources.takeIf { it.isNotEmpty() }
                            ?.let { "\nDa verificare: ${it.joinToString()}" } ?: "")
                    refreshBridgeData()
                }
                return@execute
            }

            when (route) {
                Route.DIRECT -> fallbackToP2p()
                Route.P2P -> fallbackToRelay(RelayFallbackReason.P2P_FAILED)
                Route.RESTORED -> fallbackStoredToRelay()
                Route.RELAY -> runOnUiThread {
                    setBusy(false)
                    diagnosticsText.text =
                        "Tunnel attivo ma Bridge non raggiungibile: ${diagnostics.error ?: "errore sconosciuto"}"
                }
            }
        }
    }

    private fun fallbackToP2p() {
        val current = provisioned
        if (current == null) {
            fallbackStoredToRelay()
            return
        }
        route = Route.P2P
        renderRouteOnUi()
        probeGeneration.incrementAndGet()
        val result = runCatching { runtime.session.connectPreferP2P(current) }
        if (result.getOrNull() == null) {
            fallbackToRelay(RelayFallbackReason.DIRECT_FAILED)
        }
    }

    private fun fallbackToRelay(reason: RelayFallbackReason) {
        val current = provisioned
        if (current == null) {
            fallbackStoredToRelay()
            return
        }
        if (!current.enrollment.relay.enabled) {
            runOnUiThread {
                setBusy(false)
                diagnosticsText.text = "Direct e P2P non raggiungibili. Relay non configurato sul Bridge."
            }
            return
        }
        route = Route.RELAY
        renderRouteOnUi()
        probeGeneration.incrementAndGet()
        val result = runCatching { runtime.session.connectViaRelayAfterFailure(current, reason) }
        if (result.isFailure) {
            runOnUiThread {
                setBusy(false)
                diagnosticsText.text = "Fallback Relay fallito: ${friendlyError(result.exceptionOrNull())}"
            }
        }
    }

    private fun fallbackStoredToRelay() {
        route = Route.RELAY
        renderRouteOnUi()
        probeGeneration.incrementAndGet()
        val result = runCatching {
            runtime.connectStoredViaRelayAfterFailure(RelayFallbackReason.CONTROL_UNREACHABLE)
        }
        if (result.isFailure) {
            runOnUiThread {
                setBusy(false)
                diagnosticsText.text =
                    "Bridge non raggiungibile con configurazione salvata: ${friendlyError(result.exceptionOrNull())}"
            }
        }
    }

    private fun refreshBridgeData() {
        setBusy(true)
        worker.execute {
            val started = SystemClock.elapsedRealtime()
            val result = runCatching {
                val status = JSONObject(runtime.session.status().json)
                val latency = SystemClock.elapsedRealtime() - started
                val resources = runtime.session.resources()
                Triple(status, resources, latency)
            }
            runOnUiThread {
                setBusy(false)
                result.onSuccess { (status, resources, latency) ->
                    val device = status.optString("device").ifBlank {
                        status.optString("device_id").ifBlank { "—" }
                    }
                    val vpn = status.optString("vpn_ip").ifBlank {
                        provisioned?.enrollment?.vpnIp ?: "—"
                    }
                    detailsText.text =
                        "Health: ONLINE · ${latency} ms\nDevice: $device · VPN: $vpn\nURL: http://10.88.0.1:8788/v1/status"
                    renderResources(resources)
                    refreshCatalog()
                }.onFailure {
                    diagnosticsText.text = "Diagnostica non disponibile: ${friendlyError(it)}"
                }
            }
        }
    }

    private fun refreshCatalog() {
        worker.execute {
            val result = runCatching { loadCatalogSummary() }
            runOnUiThread {
                catalogText.text = result.getOrElse {
                    "Catalogo multi-server non disponibile: ${friendlyError(it)}"
                }
            }
        }
    }

    private fun loadCatalogSummary(): String {
        val connection = URL("http://10.88.0.1:8788/v1/catalog").openConnection() as HttpURLConnection
        connection.connectTimeout = 4000
        connection.readTimeout = 4000
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/json")
        val code = connection.responseCode
        val body = (if (code in 200..299) connection.inputStream else connection.errorStream)
            ?.bufferedReader()?.use { it.readText() }.orEmpty()
        require(code in 200..299) { "HTTP $code" }

        val json = JSONObject(body)
        val schema = json.optString("schema").ifBlank { "catalogo GE360" }
        val servers = json.optJSONArray("servers")
        val resources = json.optJSONArray("resources") ?: json.optJSONArray("items")

        val serverNames = buildList {
            if (servers != null) {
                for (i in 0 until servers.length()) {
                    val item = servers.optJSONObject(i) ?: continue
                    val name = item.optString("name").ifBlank {
                        item.optString("server_id").ifBlank { "server-${i + 1}" }
                    }
                    add(name)
                }
            }
        }

        return buildString {
            append(schema)
            if (servers != null) append("\nServer: ${servers.length()}")
            if (resources != null) append(" · Resource: ${resources.length()}")
            if (serverNames.isNotEmpty()) append("\n").append(serverNames.joinToString(" · "))
        }
    }

    private fun renderResources(resources: List<BridgeResource>) {
        resourcesBox.removeAllViews()
        if (resources.isEmpty()) {
            resourcesBox.addView(valueText("Nessuna Resource autorizzata."))
            return
        }

        resources.forEach { resource ->
            val item = MaterialCardView(this).apply {
                radius = dp(14).toFloat()
                cardElevation = 0f
                isClickable = resource.launchable && resource.url.isNotBlank()
                isFocusable = isClickable
            }
            val body = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(14), dp(10), dp(14), dp(10))
                addView(TextView(this@MainActivity).apply {
                    text = resource.name
                    textSize = 16f
                    typeface = Typeface.DEFAULT_BOLD
                })
                addView(TextView(this@MainActivity).apply {
                    text = buildString {
                        if (resource.description.isNotBlank()) append(resource.description)
                        if (resource.healthState != null) {
                            if (isNotEmpty()) append("\n")
                            append("Health: ").append(resource.healthState)
                        }
                        if (resource.bridgePort > 0) {
                            if (isNotEmpty()) append(" · ")
                            append("porta ").append(resource.bridgePort)
                        }
                    }.ifBlank { "Resource GE360" }
                    alpha = 0.74f
                })
            }
            item.addView(body)
            if (resource.launchable && resource.url.isNotBlank()) {
                item.setOnClickListener {
                    runCatching {
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(resource.url)))
                    }.onFailure {
                        snackbar("Nessuna app disponibile per aprire la Resource")
                    }
                }
            }
            resourcesBox.addView(item, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dp(8)
            })
        }
    }

    private fun confirmForget() {
        AlertDialog.Builder(this)
            .setTitle("Dimenticare il Bridge?")
            .setMessage("Cancella la configurazione cifrata del tunnel da questo telefono. Per riconnetterti servirà un nuovo QR.")
            .setNegativeButton("Annulla", null)
            .setPositiveButton("Dimentica") { _, _ ->
                probeGeneration.incrementAndGet()
                provisioned = null
                runtime.vpnController.forget()
                route = Route.RESTORED
                renderRoute()
                detailsText.text = "Bridge: non associato"
                diagnosticsText.text = "Configurazione locale cancellata."
                catalogText.text = "Catalogo non ancora letto."
                renderResources(emptyList())
            }
            .show()
    }

    private fun renderState(state: ConnectionState) {
        stateText.text = when (state) {
            ConnectionState.DISCONNECTED -> "● DISCONNESSO"
            ConnectionState.WAITING_PERMISSION -> "● CONSENSO VPN RICHIESTO"
            ConnectionState.CONNECTING -> "● CONNESSIONE…"
            ConnectionState.CONNECTED -> "● CONNESSO"
            ConnectionState.RECONNECTING -> "● RICONNESSIONE…"
            ConnectionState.ERROR -> "● ERRORE"
        }
        if (state == ConnectionState.ERROR) {
            val error = runtime.vpnController.lastError()
            diagnosticsText.text = "Errore tunnel: ${error ?: "sconosciuto"}"
        }
    }

    private fun renderRoute() {
        routeText.text = "Percorso: ${route.label}"
    }

    private fun renderRouteOnUi() = runOnUiThread { renderRoute() }

    private fun setBusy(value: Boolean) = runOnUiThread {
        progress.visibility = if (value) View.VISIBLE else View.GONE
    }

    private fun snackbar(message: String) {
        Snackbar.make(root, message, Snackbar.LENGTH_LONG).show()
    }

    private fun friendlyError(error: Throwable?): String {
        if (error == null) return "errore sconosciuto"
        return error.message?.takeIf { it.isNotBlank() }
            ?: error.javaClass.simpleName
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()
}
