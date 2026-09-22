# Pairing sicuro v2

Schema QR: `ge360-bridge-pairing/v2`.

La Fase 3 sostituisce il flusso di creazione dei nuovi device: la private key WireGuard del client non viene più generata dal Bridge e non compare mai nel QR.

## Flusso

1. L'amministratore crea un invito pairing dalla dashboard o con `ge360-bridge device-add`.
2. Il Bridge genera un token casuale monouso.
3. Nello stato persistente viene salvato solo l'HMAC SHA-256 del token.
4. Il QR contiene enrollment ID, token, URL HTTPS, fingerprint TLS e dati pubblici WireGuard del server.
5. Il client verifica che il certificato HTTPS presentato dal server corrisponda esattamente a `tls_cert_sha256`.
6. Il client genera localmente la propria coppia WireGuard private/public key.
7. Il client invia al Bridge soltanto `enrollment_id`, `token` e `public_key`.
8. Il Bridge valida token, TTL, stato e public key.
9. Il Bridge crea il device, assegna IP VPN e PSK, applica gli eventuali gruppi iniziali e marca l'enrollment `used`.
10. Ogni replay dello stesso token viene rifiutato.

## Payload QR

Esempio:

```json
{
  "schema": "ge360-bridge-pairing/v2",
  "enrollment_id": "enr_...",
  "device": "telefono-milan",
  "enrollment_url": "https://203.0.113.10:8790/v2/enroll",
  "token": "...",
  "expires_at": 1790070000,
  "tls_cert_sha256": "...",
  "wireguard": {
    "server_public_key": "...",
    "endpoint": "203.0.113.10:51820",
    "allowed_ips": "10.88.0.1/32",
    "persistent_keepalive": 25
  }
}
```

Il token è sensibile ma non contiene una private key.

## Richiesta enrollment

Il client effettua:

```http
POST /v2/enroll
Content-Type: application/json
```

Body:

```json
{
  "enrollment_id": "enr_...",
  "token": "...",
  "public_key": "WIREGUARD_PUBLIC_KEY_GENERATA_DAL_CLIENT"
}
```

Prima del POST il client deve verificare il fingerprint SHA-256 del certificato TLS contro `tls_cert_sha256` del QR.

## Risposta

La risposta contiene soltanto il materiale necessario a completare la configurazione client:

- device_id;
- VPN IP;
- PSK;
- device token applicativo;
- public key WireGuard server;
- endpoint WireGuard;
- AllowedIPs `10.88.0.1/32`;
- eventuali gruppi e servizi effettivi;
- `runtime_sync` per indicare se il Bridge ha applicato subito la nuova configurazione.

La private key client rimane esclusivamente sul client.

## TTL e replay

TTL ammesso: 60..86400 secondi.

Stati:
- `pending`;
- `used`;
- `expired`.

Dopo il primo enrollment valido il record passa atomicamente a `used`. I record terminali vengono mantenuti temporaneamente per distinguere un replay da un invito sconosciuto.

## HTTPS bootstrap

Il servizio di enrollment ascolta sulla porta TCP `8790` ed espone solo:

- `GET /healthz`;
- `POST /v2/enroll`.

Non espone dashboard o API amministrative.

Il certificato self-signed viene creato una sola volta dall'installer e preservato negli aggiornamenti. La sicurezza dell'identità server deriva dal certificate pinning tramite il fingerprint inserito nel QR.

## Limite rete

Il client deve poter raggiungere la porta TCP 8790 prima di avere il tunnel WireGuard. Se il server è dietro CGNAT senza IPv6 globale o port forwarding raggiungibile, il pairing remoto diretto non può funzionare. NAT traversal appartiene alle Fasi 18-19 e non viene anticipato qui.
