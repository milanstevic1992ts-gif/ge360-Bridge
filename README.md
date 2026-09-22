# GE360 Universal Bridge

Ponte privato e riutilizzabile per collegare i frontend GE360 ai backend Linux anche fuori dalla LAN, senza esporre direttamente le API applicative.

## Obiettivo

Un solo Bridge sul server gestisce più app e più backend. La rete privata usa WireGuard `wg0` su `10.88.0.0/24`, UDP `51820`. La modalità predefinita è **Server Only**: il client può raggiungere `10.88.0.1`, non la LAN e non Internet attraverso il server.

## Dashboard amministratore

La v0.2 aggiunge una dashboard separata dal proxy:

- server locale: `http://127.0.0.1:8789`
- tramite WireGuard: `http://10.88.0.1:8789`
- health: `http://127.0.0.1:8789/healthz`
- stato JSON autenticato: `/api/status`

Il token amministratore è generato una sola volta e preservato negli aggiornamenti:

```bash
sudo cat /etc/ge360-bridge/dashboard.token
```

La dashboard mostra dispositivi online/offline, ultimo handshake WireGuard, endpoint del peer, traffico RX/TX, backend raggiungibili, porte Bridge e ACL. Permette anche di creare dispositivi con QR, revocarli, registrare/rimuovere backend e modificare i permessi.

## Installazione / aggiornamento Debian 13

```bash
git clone https://github.com/milanstevic1992ts-gif/ge360-Bridge.git
cd ge360-Bridge
sudo ./install.sh
```

Se la repo è già installata:

```bash
cd ge360-Bridge
git pull
sudo ./install.sh
```

L'installer preserva chiavi, endpoint, peer, dispositivi, servizi e token dashboard esistenti.

## Pairing di un telefono

Da terminale:

```bash
sudo ge360-bridge device-add telefono-milan
```

Oppure dalla dashboard con **Aggiungi dispositivo**. Il pairing temporaneo della dashboard resta recuperabile per 30 minuti.

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

Il frontend autorizzato usa `http://10.88.0.1:9888`.

Ogni frontend può verificare il Bridge senza toccare il backend su `http://10.88.0.1:8788/v1/status`.

## Diagnostica

```bash
ge360-bridge status
sudo wg show
systemctl status wg-quick@wg0 ge360-bridge ge360-bridge-dashboard ge360-bridge-firewall
curl http://127.0.0.1:8789/healthz
journalctl -u ge360-bridge -u ge360-bridge-dashboard -n 100 --no-pager
```

## Gestione permessi e revoca

```bash
sudo ge360-bridge service-grant rilievi telefono-milan
sudo ge360-bridge service-revoke rilievi telefono-milan
sudo ge360-bridge device-revoke telefono-milan
```

## Sicurezza

- chiave WireGuard e PSK distinti per ogni device;
- token applicativo dedicato per dispositivo;
- token amministratore dashboard separato;
- dashboard in ascolto solo su localhost e IP WireGuard;
- backend non pubblicati sulla WAN;
- ACL per dispositivo su ogni servizio;
- traffico da `wg0` non inoltrato alla LAN;
- pairing dashboard temporanei con permessi `0600` e TTL 30 minuti;
- file sensibili `0600`;
- la porta WAN UDP `51820` non viene aperta forzando o sostituendo il firewall generale del server.

## Nota su CGNAT

Senza IPv4 pubblica/port-forward oppure IPv6 globale raggiungibile, una connessione **diretta** da Internet al server non può funzionare. In quel caso il Bridge segnala la condizione invece di introdurre di nascosto relay o cloud esterni.

Vedi `docs/ARCHITECTURE.md`, `docs/PAIRING_PROTOCOL.md`, `docs/SECURITY.md` e `docs/DASHBOARD.md`.
