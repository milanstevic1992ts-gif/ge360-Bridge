package com.ge360.bridge

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import java.io.ByteArrayInputStream
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class AndroidWireGuardKeyProvider : WireGuardKeyProvider {
    override fun generate(): WireGuardKeyMaterial {
        val pair = KeyPair()
        return WireGuardKeyMaterial(
            privateKey = pair.privateKey.toBase64(),
            publicKey = pair.publicKey.toBase64()
        )
    }
}

fun interface ConnectionStateListener {
    fun onStateChanged(state: ConnectionState)
}

data class ReconnectPolicy(
    val maxAttempts: Int = 6,
    val initialDelayMs: Long = 1_000,
    val maxDelayMs: Long = 30_000
) {
    init {
        require(maxAttempts >= 1)
        require(initialDelayMs >= 0)
        require(maxDelayMs >= initialDelayMs)
    }

    fun delayForAttempt(attempt: Int): Long {
        require(attempt >= 1)
        var delay = initialDelayMs
        repeat((attempt - 1).coerceAtMost(30)) {
            delay = (delay * 2).coerceAtMost(maxDelayMs)
        }
        return delay
    }
}

internal interface WireGuardBackend {
    fun up(config: WireGuardConfig)
    fun down()
    fun isUp(): Boolean
    fun setStateListener(listener: (Boolean) -> Unit) {}
}

internal class GoWireGuardBackend(
    context: Context,
    tunnelName: String = "ge360bridge",
    private val onTunnelState: (Tunnel.State) -> Unit = {}
) : WireGuardBackend {
    private val backend = GoBackend(context.applicationContext)
    @Volatile private var stateListener: ((Boolean) -> Unit)? = null
    private val tunnel: Tunnel

    init {
        require(!Tunnel.isNameInvalid(tunnelName)) { "Nome tunnel WireGuard non valido" }
        tunnel = object : Tunnel {
            override fun getName(): String = tunnelName
            override fun onStateChange(newState: Tunnel.State) {
                onTunnelState(newState)
                stateListener?.invoke(newState == Tunnel.State.UP)
            }
        }
    }

    override fun up(config: WireGuardConfig) {
        val parsed = Config.parse(
            ByteArrayInputStream(config.asText().toByteArray(Charsets.UTF_8))
        )
        val result = backend.setState(tunnel, Tunnel.State.UP, parsed)
        check(result == Tunnel.State.UP) { "WireGuard non è salito" }
    }

    override fun down() {
        backend.setState(tunnel, Tunnel.State.DOWN, null)
    }

    override fun isUp(): Boolean = backend.getState(tunnel) == Tunnel.State.UP

    override fun setStateListener(listener: (Boolean) -> Unit) {
        stateListener = listener
    }
}

class AndroidWireGuardController internal constructor(
    private val appContext: Context,
    private val backend: WireGuardBackend,
    private val store: SecureTunnelStore,
    private val reconnectPolicy: ReconnectPolicy = ReconnectPolicy(),
    autoRestore: Boolean = true
) : VpnController, AutoCloseable {
    constructor(
        context: Context,
        reconnectPolicy: ReconnectPolicy = ReconnectPolicy(),
        autoRestore: Boolean = true
    ) : this(
        appContext = context.applicationContext,
        backend = GoWireGuardBackend(context.applicationContext),
        store = SecureTunnelStore(context.applicationContext),
        reconnectPolicy = reconnectPolicy,
        autoRestore = autoRestore
    )

    private val executor = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "ge360-wireguard").apply { isDaemon = true }
    }
    private val stateRef = AtomicReference(ConnectionState.DISCONNECTED)
    private val listeners = CopyOnWriteArraySet<ConnectionStateListener>()
    private val connectivity = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val lock = Any()

    @Volatile private var desiredConnected = false
    @Volatile private var currentConfig: WireGuardConfig? = null
    @Volatile private var retryAttempt = 0
    @Volatile private var retryFuture: ScheduledFuture<*>? = null
    @Volatile private var lastErrorValue: String? = null
    @Volatile private var networkWasLost = false
    @Volatile private var internalTransition = false

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onLost(network: Network) {
            if (!desiredConnected) return
            networkWasLost = true
            setState(ConnectionState.RECONNECTING)
            scheduleReconnect(forceCycle = true, immediate = false)
        }

        override fun onAvailable(network: Network) {
            if (!desiredConnected) return
            val shouldCycle = networkWasLost
            if (shouldCycle || state() == ConnectionState.ERROR || state() == ConnectionState.RECONNECTING) {
                networkWasLost = false
                scheduleReconnect(forceCycle = shouldCycle, immediate = true)
            }
        }
    }

    init {
        backend.setStateListener { isUp ->
            if (internalTransition) return@setStateListener
            if (isUp) {
                retryAttempt = 0
                lastErrorValue = null
                setState(ConnectionState.CONNECTED)
            } else if (desiredConnected) {
                setState(ConnectionState.RECONNECTING)
                scheduleReconnect(forceCycle = false, immediate = false)
            } else {
                setState(ConnectionState.DISCONNECTED)
            }
        }
        runCatching { connectivity.registerDefaultNetworkCallback(networkCallback) }
        GoBackend.setAlwaysOnCallback {
            restoreLastTunnel()
        }
        if (autoRestore) restoreLastTunnel()
    }

    override fun state(): ConnectionState = stateRef.get()

    fun lastError(): String? = lastErrorValue

    fun addStateListener(listener: ConnectionStateListener) {
        listeners.add(listener)
        listener.onStateChanged(state())
    }

    fun removeStateListener(listener: ConnectionStateListener) {
        listeners.remove(listener)
    }

    fun vpnPermissionIntent(): Intent? = VpnService.prepare(appContext)

    fun requiresVpnPermission(): Boolean = vpnPermissionIntent() != null

    fun onVpnPermissionResult(granted: Boolean) {
        if (!granted) {
            lastErrorValue = "VPN_PERMISSION_DENIED"
            setState(ConnectionState.ERROR)
            return
        }
        if (desiredConnected) scheduleReconnect(forceCycle = false, immediate = true)
    }

    override fun start(config: WireGuardConfig) {
        validateRestrictedRoute(config)
        synchronized(lock) {
            currentConfig = config
            desiredConnected = true
            retryAttempt = 0
            lastErrorValue = null
            store.save(config, desiredConnected = true)
        }
        if (requiresVpnPermission()) {
            setState(ConnectionState.WAITING_PERMISSION)
            return
        }
        scheduleReconnect(forceCycle = false, immediate = true)
    }

    override fun startTransient(config: WireGuardConfig) {
        validateRestrictedRoute(config)
        synchronized(lock) {
            currentConfig = config
            desiredConnected = true
            retryAttempt = 0
            lastErrorValue = null
            store.setDesiredConnected(true)
        }
        if (requiresVpnPermission()) {
            setState(ConnectionState.WAITING_PERMISSION)
            return
        }
        scheduleReconnect(forceCycle = true, immediate = true)
    }

    fun connectStoredViaRelayAfterFailure(
        reason: RelayFallbackReason,
        relayClient: RelayFallbackClient = RelayFallbackClient()
    ): RelayPlan {
        val base = store.load()?.config ?: currentConfig
            ?: throw IllegalStateException("Configurazione GE360 non disponibile")
        val plan = relayClient.requestAndWait(base, reason)
        startTransient(base.copy(endpoint = plan.clientEndpoint, listenPort = 0))
        return plan
    }

    override fun stop() {
        synchronized(lock) {
            desiredConnected = false
            retryAttempt = 0
            retryFuture?.cancel(false)
            retryFuture = null
            store.setDesiredConnected(false)
        }
        executor.execute {
            internalTransition = true
            try {
                runCatching { backend.down() }
            } finally {
                internalTransition = false
            }
            setState(ConnectionState.DISCONNECTED)
        }
    }

    fun forget() {
        stop()
        synchronized(lock) {
            currentConfig = null
            store.clear()
        }
    }

    fun restoreLastTunnel() {
        val stored = store.load() ?: return
        synchronized(lock) {
            currentConfig = stored.config
            desiredConnected = stored.desiredConnected
            retryAttempt = 0
        }
        if (!stored.desiredConnected) return
        if (requiresVpnPermission()) {
            setState(ConnectionState.WAITING_PERMISSION)
            return
        }
        scheduleReconnect(forceCycle = false, immediate = true)
    }

    private fun scheduleReconnect(forceCycle: Boolean, immediate: Boolean) {
        synchronized(lock) {
            if (!desiredConnected || currentConfig == null) return
            retryFuture?.cancel(false)
            val delay = if (immediate) 0 else reconnectPolicy.delayForAttempt((retryAttempt + 1).coerceAtLeast(1))
            retryFuture = executor.schedule(
                { connectAttempt(forceCycle) },
                delay,
                TimeUnit.MILLISECONDS
            )
        }
    }

    private fun connectAttempt(forceCycle: Boolean) {
        val config = currentConfig ?: return
        if (!desiredConnected) return

        if (requiresVpnPermission()) {
            setState(ConnectionState.WAITING_PERMISSION)
            return
        }

        val isRetry = retryAttempt > 0 || forceCycle
        setState(if (isRetry) ConnectionState.RECONNECTING else ConnectionState.CONNECTING)

        try {
            internalTransition = true
            if (forceCycle && backend.isUp()) {
                backend.down()
            }
            backend.up(config)
            retryAttempt = 0
            lastErrorValue = null
            setState(ConnectionState.CONNECTED)
        } catch (exc: Exception) {
            lastErrorValue = exc.javaClass.simpleName
            retryAttempt += 1
            if (!desiredConnected) {
                setState(ConnectionState.DISCONNECTED)
                return
            }
            if (retryAttempt >= reconnectPolicy.maxAttempts) {
                setState(ConnectionState.ERROR)
                return
            }
            setState(ConnectionState.RECONNECTING)
            scheduleReconnect(forceCycle = false, immediate = false)
        } finally {
            internalTransition = false
        }
    }

    private fun validateRestrictedRoute(config: WireGuardConfig) {
        val routes = config.allowedIps.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        require(routes == listOf("10.88.0.1/32")) {
            "GE360 Bridge richiede AllowedIPs = 10.88.0.1/32"
        }
    }

    private fun setState(newState: ConnectionState) {
        val old = stateRef.getAndSet(newState)
        if (old == newState) return
        listeners.forEach { listener ->
            runCatching { listener.onStateChanged(newState) }
        }
    }

    override fun close() {
        retryFuture?.cancel(false)
        runCatching { connectivity.unregisterNetworkCallback(networkCallback) }
        if (desiredConnected) {
            internalTransition = true
            runCatching { backend.down() }
            internalTransition = false
        }
        desiredConnected = false
        executor.shutdownNow()
    }
}

data class AndroidBridgeRuntime(
    val session: BridgeSession,
    val vpnController: AndroidWireGuardController
) : AutoCloseable {
    fun vpnPermissionIntent(): Intent? = vpnController.vpnPermissionIntent()
    fun onVpnPermissionResult(granted: Boolean) = vpnController.onVpnPermissionResult(granted)
    fun restore() = vpnController.restoreLastTunnel()
    fun connectStoredViaRelayAfterFailure(
        reason: RelayFallbackReason,
        relayClient: RelayFallbackClient = RelayFallbackClient()
    ): RelayPlan = vpnController.connectStoredViaRelayAfterFailure(reason, relayClient)
    override fun close() = vpnController.close()
}

object Ge360AndroidBridge {
    fun create(
        context: Context,
        reconnectPolicy: ReconnectPolicy = ReconnectPolicy(),
        autoRestore: Boolean = true
    ): AndroidBridgeRuntime {
        val controller = AndroidWireGuardController(context, reconnectPolicy, autoRestore)
        val session = BridgeSession(
            keyProvider = AndroidWireGuardKeyProvider(),
            vpnController = controller
        )
        return AndroidBridgeRuntime(session, controller)
    }
}
