# GE360 Bridge Android App

App Android installabile che usa direttamente il modulo `ge360-bridge-android`.

## Funzioni

- scansione QR pairing v2;
- alternativa incolla-payload;
- enrollment con certificate pinning;
- consenso Android VpnService;
- tunnel WireGuard limitato a `10.88.0.1/32`;
- riconnessione automatica dell'SDK;
- percorso di fallback Direct → P2P → Relay;
- ripristino della configurazione cifrata con Android Keystore;
- stato tunnel e health Bridge separati;
- diagnostica;
- Resource autorizzate;
- lettura del catalogo multi-server `/v1/catalog`;
- disconnect e forget espliciti.

## Build locale

```bash
gradle -p android-sdk :ge360-bridge-app:assembleDebug
```

APK:

```text
android-sdk/ge360-bridge-app/build/outputs/apk/debug/ge360-bridge-app-debug.apk
```

## CI

La workflow `Android APK` compila e pubblica l'artifact `GE360-Bridge-APK`.

L'APK debug è firmato automaticamente da Android per test/installazione. Per aggiornamenti di produzione va configurata una chiave privata di release stabile; una chiave di firma non deve essere committata nella repository pubblica.
