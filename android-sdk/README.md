# GE360 Bridge Android SDK — Fase 12

Modulo:

```text
android-sdk/ge360-bridge-android
```

## Funzioni completate

Fase 11:

- QR pairing v2;
- certificate pinning;
- enrollment;
- Resource discovery;
- diagnostica SDK.

Fase 12:

- backend WireGuard ufficiale;
- `AndroidWireGuardKeyProvider`;
- `AndroidWireGuardController`;
- Android VpnService permission flow;
- reconnect Wi-Fi/mobile;
- backoff;
- stati connessione;
- configurazione tunnel cifrata con Android Keystore;
- auto-restore;
- Network Security Config per il Bridge privato.

## Setup

```kotlin
val ge360 = Ge360AndroidBridge.create(context)
val provisioned = ge360.session.provision(qrPayload)
ge360.session.connect(provisioned)

ge360.vpnPermissionIntent()?.let { intent ->
    // avvia il launcher ActivityResult per il consenso VPN
}
```

Dopo il consenso:

```kotlin
ge360.onVpnPermissionResult(true)
```

## Stati

```text
DISCONNECTED
WAITING_PERMISSION
CONNECTING
CONNECTED
RECONNECTING
ERROR
```

## Sicurezza

Il tunnel resta ristretto a:

```text
10.88.0.1/32
```

Private key e PSK vengono persistite solo cifrate con Android Keystore.

## Confine Fase 12/13

La Fase 12 non implementa `/.well-known/ge360` né auto-discovery backend.

La Fase 13 resta separata.
