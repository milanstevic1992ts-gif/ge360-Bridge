# GE360 Universal Bridge

Versione corrente: **v0.14 — Fase 12: Connessione automatica Android**.

La fonte di verità resta `docs/ROADMAP.md`.

## Android automatic connection

Il modulo `ge360-bridge-android` ora integra:

- WireGuard Android ufficiale;
- `GoBackend`;
- Android VpnService;
- consenso VPN;
- reconnect;
- backoff;
- stato connessione;
- auto-restore;
- persistenza cifrata Android Keystore.

Il tunnel resta limitato a:

```text
10.88.0.1/32
```

## Integrazione

```kotlin
val ge360 = Ge360AndroidBridge.create(context)
val provisioned = ge360.session.provision(qrPayload)
ge360.session.connect(provisioned)
```

Se Android richiede il consenso VPN, usa `ge360.vpnPermissionIntent()` e passa l'esito a `ge360.onVpnPermissionResult(...)`.

## Fase successiva

L'auto-discovery backend `/.well-known/ge360` appartiene alla Fase 13 e non è stato implementato.

Vedi:

```text
docs/ANDROID_CONNECTION.md
android-sdk/README.md
```
