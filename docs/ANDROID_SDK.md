# Frontend SDK Android — Fase 11 — COMPLETATA

La Fase 11 introduce il modulo riutilizzabile `ge360-bridge-android`.

## Componenti

### QrPairingScanner

Decodifica un QR da `android.graphics.Bitmap` con ZXing Core e passa il testo al parser v2.

### QrPairingParser

Valida:

- schema v2;
- enrollment HTTPS;
- fingerprint TLS SHA-256;
- token;
- dati pubblici WireGuard.

### EnrollmentClient

Esegue enrollment HTTPS usando il fingerprint del QR come identità autoritativa del certificato self-signed.

Invia soltanto:

- enrollment_id;
- token;
- public key client.

La private key non viene trasmessa.

### WireGuardKeyProvider

Contratto per il generatore chiavi scelto dall'app/implementazione VPN.

L'SDK non implementa Curve25519 in modo proprietario.

### VpnController

Contratto riutilizzabile:

- state;
- start;
- stop.

L'implementazione Android automatica appartiene alla Fase 12.

### BridgeApiClient

Supporta:

- `/v1/status`;
- `/v1/resources`;
- Resource discovery;
- diagnostica client leggera basata sullo stato visibile al device.

### BridgeSession

Orchestra:

```text
QR
→ parser
→ key provider
→ enrollment
→ WireGuardConfig
→ VpnController
→ status/resources/diagnostics
```

## Sicurezza

Oggetti contenenti token, PSK o private key hanno `toString()` redatto.

Il certificato enrollment viene accettato soltanto se la sua impronta SHA-256 coincide esattamente col pin del QR.

## Build CI

Workflow dedicata Android con JDK 17, SDK 35 e Gradle.

## Chiusura Fase 11

Criteri verificati:

- modulo Android compilato;
- test Kotlin parser/configurazione verdi;
- CI Python verde;
- CI Android verde;
- pairing v2 e certificate pinning presenti;
- private key non inviata dal client;
- segreti redatti nei modelli sensibili;
- nessuna implementazione automatica di VpnService/reconnect introdotta.

## Fuori scope

VpnService Android, reconnect automatico e persistenza sicura della configurazione appartengono alla Fase 12, non avviata.
