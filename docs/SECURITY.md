# Sicurezza

Principi di default:

- nessun backend esposto direttamente su WAN;
- WireGuard con chiave distinta per ogni dispositivo;
- PSK distinta per ogni peer;
- token applicativo distinto per dispositivo;
- `AllowedIPs = 10.88.0.1/32` lato client;
- niente forwarding da `wg0` verso LAN o Internet;
- ACL servizio/dispositivo nel proxy;
- file chiavi e stato con permessi `0600`;
- revoca immediata del peer con `ge360-bridge device-revoke`.

Il QR di pairing contiene materiale segreto e va trattato come una password. Non va committato, inviato su chat pubbliche o inserito nei log.
