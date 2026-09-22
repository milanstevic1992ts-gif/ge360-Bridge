# GE360 Universal Bridge

Ponte privato e riutilizzabile per collegare i frontend GE360 ai backend Linux anche fuori dalla LAN, senza esporre direttamente le API applicative.

## Obiettivo

Un solo Bridge sul server gestisce più app e più backend. La rete privata usa WireGuard `wg0` su `10.88.0.0/24`, UDP `51820`. La modalità predefinita è **Server Only**: il client può raggiungere `10.88.0.1`, non la LAN e non Internet attraverso il server.

## Installazione Debian 13

```bash
git clone https://github.com/milanstevic1992ts-gif/ge360-Bridge.git
cd ge360-Bridge
sudo ./install.sh
```

Poi imposta `PUBLIC_ENDPOINT` in `/etc/ge360-bridge/bridge.env` se l'installer non riesce a determinarlo.

## Pairing di un telefono

```bash
sudo ge360-bridge device-add telefono-milan
```

Viene mostrato un QR `ge360-bridge-pairing/v1` con configurazione WireGuard, IP del Bridge e token dispositivo.

## Collegare GE360 Rilievi

Il backend deve preferibilmente ascoltare solo in locale:

```text
127.0.0.1:9888
```

Poi:

```bash
sudo ge360-bridge service-add rilievi \
  --port 9888 \
  --target-host 127.0.0.1 \
  --target-port 9888 \
  --allow telefono-milan
```

Il frontend autorizzato usa:

```text
http://10.88.0.1:9888
```

Ogni frontend può inoltre verificare il Bridge senza toccare il backend:

```text
http://10.88.0.1:8788/v1/status
```

Questo endpoint restituisce lo stato del tunnel e l'elenco dei servizi consentiti a quel dispositivo; è pensato anche per una pagina **Connessione Bridge** dentro le app GE360.

## Diagnostica

```bash
ge360-bridge status
sudo wg show
systemctl status wg-quick@wg0 ge360-bridge ge360-bridge-firewall
journalctl -u ge360-bridge -n 100 --no-pager
```

## Gestione permessi e revoca

```bash
sudo ge360-bridge service-grant rilievi telefono-milan
sudo ge360-bridge service-revoke rilievi telefono-milan
sudo ge360-bridge device-revoke telefono-milan
```

## Sicurezza

- chiave WireGuard e PSK per ogni device;
- token applicativo dedicato, mai master key;
- backend non pubblicati sulla WAN;
- ACL per dispositivo su ogni servizio;
- traffico da `wg0` non inoltrato alla LAN;
- file sensibili `0600`;
- la porta WAN UDP `51820` non viene aperta forzando o sostituendo il firewall generale del server: se usi UFW/nftables con policy restrittive, autorizzala esplicitamente sul firewall host/router.

## Nota su CGNAT

Senza IPv4 pubblica/port-forward oppure IPv6 globale raggiungibile, una connessione **diretta** da Internet al server non può funzionare. In quel caso il Bridge segnala la condizione invece di introdurre di nascosto relay o cloud esterni.

Vedi `docs/ARCHITECTURE.md`, `docs/PAIRING_PROTOCOL.md` e `docs/SECURITY.md`.
