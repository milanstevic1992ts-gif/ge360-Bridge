# GE360 Universal Bridge

Versione corrente: **v0.13 — Fase 11 completata: Frontend SDK Android**. La Fase 12 è la prossima e non è ancora stata avviata.

La fonte di verità resta `docs/ROADMAP.md`.

## Android SDK

Modulo riutilizzabile:

```text
android-sdk/ge360-bridge-android
```

Include:

- QR scanner/parser v2;
- enrollment con TLS certificate pinning;
- WireGuard config;
- `WireGuardKeyProvider`;
- `VpnController`;
- stato connessione;
- status/health;
- Resource discovery;
- diagnostica SDK.

La connessione Android automatica tramite VpnService appartiene alla Fase 12, che non è stata avviata.

## CI

La repository ora ha anche una workflow **Android SDK** che compila e testa il modulo.

Vedi:

```text
android-sdk/README.md
docs/ANDROID_SDK.md
```
