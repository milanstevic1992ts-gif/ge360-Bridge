# Connessione automatica Android — Fase 12

La Fase 12 completa il lato Android del GE360 Universal Bridge usando il backend WireGuard ufficiale.

## Motore WireGuard

Dipendenza:

```text
com.wireguard.android:tunnel:1.0.20260315
```

Il controller usa `GoBackend`, quindi il tunnel funziona tramite il `VpnService` userspace WireGuard senza richiedere root.

## Componenti

### AndroidWireGuardKeyProvider

Implementa il contratto Fase 11 `WireGuardKeyProvider` usando `KeyPair` della libreria WireGuard.

La private key resta sul dispositivo.

### AndroidWireGuardController

Implementa `VpnController` e gestisce:

- consenso Android VpnService;
- salita/discesa tunnel;
- stato connessione;
- cambio rete Wi-Fi/mobile;
- reconnect;
- backoff limitato;
- ripristino configurazione;
- callback stato.

### Stati

```text
DISCONNECTED
WAITING_PERMISSION
CONNECTING
CONNECTED
RECONNECTING
ERROR
```

### ReconnectPolicy

Default:

```text
maxAttempts = 6
initialDelay = 1s
maxDelay = 30s
```

Il backoff raddoppia fino al limite massimo.

## Rotta privata obbligatoria

La Fase 12 conserva il guardrail originale del Bridge:

```text
AllowedIPs = 10.88.0.1/32
```

Il controller rifiuta configurazioni che tentano di trasformare GE360 in una VPN Internet generale.

## Persistenza sicura

`SecureTunnelStore` conserva la configurazione necessaria al reconnect.

Private key e PSK:

- non vengono salvate in chiaro;
- sono cifrate AES-GCM;
- la chiave AES è generata e custodita in Android Keystore;
- non compaiono nei `toString()`.

Lo store salva anche l'intenzione dell'utente di mantenere il tunnel connesso.

## Ripristino

`Ge360AndroidBridge.create(..., autoRestore = true)` è il default.

Se il tunnel risultava desiderato attivo, il controller tenta il ripristino.

Se Android richiede nuovamente il consenso VPN:

```text
WAITING_PERMISSION
```

e l'APK deve mostrare il dialogo di sistema.

## Integrazione Activity

Esempio:

```kotlin
private lateinit var ge360: AndroidBridgeRuntime

private val vpnPermission = registerForActivityResult(
    ActivityResultContracts.StartActivityForResult()
) { result ->
    ge360.onVpnPermissionResult(result.resultCode == Activity.RESULT_OK)
}

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    ge360 = Ge360AndroidBridge.create(this)

    val provisioned = ge360.session.provision(qrPayload)
    ge360.session.connect(provisioned)

    ge360.vpnPermissionIntent()?.let { vpnPermission.launch(it) }
}
```

## Stato UI

```kotlin
ge360.vpnController.addStateListener { state ->
    // aggiorna badge / schermata:
    // CONNECTING, CONNECTED, RECONNECTING...
}
```

## Disconnect e forget

Disconnect mantiene la configurazione cifrata ma salva `desiredConnected=false`:

```kotlin
ge360.session.disconnect()
```

Per cancellare anche la configurazione:

```kotlin
ge360.vpnController.forget()
```

## Network Security Config

Il modulo include una configurazione che nega il cleartext di default e consente HTTP al solo indirizzo privato:

```text
10.88.0.1
```

Il traffico HTTP verso il Bridge viaggia comunque dentro WireGuard cifrato.

## Fuori scope

La Fase 12 non effettua backend auto-discovery e non interroga `/.well-known/ge360`.

Questa funzione appartiene alla Fase 13.
