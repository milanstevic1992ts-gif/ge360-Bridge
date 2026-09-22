# GE360 Bridge Android SDK

Modulo:

```text
android-sdk/ge360-bridge-android
```

## Funzioni Fase 11

- decode QR v2 da `Bitmap` con ZXing;
- parse payload pairing v2;
- HTTPS enrollment con certificate pinning SHA-256;
- il server riceve solo la public key client;
- generazione chiavi delegata a `WireGuardKeyProvider`;
- creazione configurazione WireGuard;
- contratto `VpnController`;
- stato connessione;
- client `/v1/status`;
- discovery `/v1/resources`;
- diagnostica SDK leggera;
- modelli Resource.

## Esempio

```kotlin
val session = BridgeSession(
    keyProvider = myWireGuardKeyProvider,
    vpnController = myVpnController
)

val provisioned = session.provision(qrPayload)
session.connect(provisioned)

val resources = session.resources()
val diagnostics = session.diagnostics()
```

## Scanner QR

Da una `Bitmap`:

```kotlin
val invitation = QrPairingScanner.decode(bitmap)
```

Oppure, se l'app usa già un proprio scanner camera, passa il testo a:

```kotlin
QrPairingParser.parse(rawQr)
```

## Confine Fase 11/12

In Fase 11 l'SDK **non avvia autonomamente Android VpnService** e non impone un backend WireGuard.

Espone invece:

```kotlin
interface WireGuardKeyProvider
interface VpnController
```

La Fase 12 implementa questi contratti per connessione automatica, reconnect e gestione VPN Android.

## Cleartext privato

Gli endpoint `10.88.0.1` sono HTTP dentro il tunnel WireGuard. L'app host deve consentire il traffico cleartext **solo per il Bridge privato** tramite Network Security Config. La Fase 12 fornirà questa configurazione nell'integrazione Android.

## Test

La workflow GitHub `Android SDK` installa Android SDK 35 e compila:

```text
:ge360-bridge-android:testDebugUnitTest
```
