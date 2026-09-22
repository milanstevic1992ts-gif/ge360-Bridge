# Dashboard amministratore

GE360 Bridge include una dashboard amministrativa separata dal proxy applicativo.

- locale server: `http://127.0.0.1:8789`
- via WireGuard: `http://10.88.0.1:8789`
- health non autenticato: `/healthz`
- stato JSON autenticato: `/api/status`

La dashboard non ascolta sulla LAN o sulla WAN. L'accesso amministrativo richiede il token salvato in `/etc/ge360-bridge/dashboard.token`.

```bash
sudo cat /etc/ge360-bridge/dashboard.token
```

Mostra stato WireGuard, ultimo handshake, endpoint peer, traffico RX/TX, backend raggiungibili, ACL e servizi. Permette di creare un dispositivo, mostrare il QR di pairing per 30 minuti, revocare device, aggiungere/rimuovere backend e modificare autorizzazioni.

I backend registrabili sono limitati a loopback (`127.0.0.1`, `::1`, `localhost`) e le porte 8788/8789 sono riservate al sistema.
