# GE360 Universal Bridge

Versione corrente: **v0.14 — Fase 12 completata: Connessione automatica Android**. La Fase 13 è la prossima e non è ancora stata avviata.

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

La Fase 13 — Auto discovery backend è la prossima e non è stata avviata. `/.well-known/ge360` non è presente nel codice della Fase 12.

Vedi:

```text
docs/ANDROID_CONNECTION.md
android-sdk/README.md
```
