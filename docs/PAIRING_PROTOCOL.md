# Pairing QR v1

Schema: `ge360-bridge-pairing/v1`.

Il QR creato da `ge360-bridge device-add NOME` contiene JSON compatto:

```json
{
  "schema":"ge360-bridge-pairing/v1",
  "device":"telefono",
  "wireguard_config_b64":"...",
  "bridge_ip":"10.88.0.1",
  "services":[{"name":"rilievi","url":"http://10.88.0.1:9888"}],
  "device_token":"..."
}
```

Il frontend deve:
1. validare lo schema;
2. importare/configurare il tunnel WireGuard mediante la propria integrazione Android;
3. salvare il token dispositivo nel keystore Android;
4. usare solo gli URL servizio presenti nel bundle;
5. non salvare il QR come immagine o loggare la configurazione WireGuard.

Il token non sostituisce WireGuard: serve come credenziale applicativa dedicata e revocabile.
