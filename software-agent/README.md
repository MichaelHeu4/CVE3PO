# CVE3PO Software Agent (Rust)

Der Agent sammelt installierte Software und sendet Snapshots an den CVE3PO Agent-Endpoint.

## Konfiguration

Der Agent liest Einstellungen in dieser Reihenfolge:
1. Environment Variablen
2. Datei aus `SOFTWARE_AGENT_CONFIG` (Default: `/etc/cve3po-agent/agent.env`)

Wichtige Keys:
- `SOFTWARE_API_URL` (required)
- `SOFTWARE_API_AUTH` = `bearer` (default) oder `x-api-key`
- `SOFTWARE_API_BEARER_TOKEN` (oder `SOFTWARE_API_KEY`)
- `HOST_IP` (optional)
- `MACHINE_ID` (optional) – überschreibt die automatisch erkannte, stabile
  Maschinen-ID (Linux `/etc/machine-id`, Windows `MachineGuid`). Sie ist der
  primäre Schlüssel, über den der Server einen Server mit mehreren IPs als **ein**
  Asset zusammenhält. Normalerweise Auto-Erkennung aktiv lassen.
- `IP_ADDRESSES` (optional, komma-separiert) – überschreibt die automatisch
  erkannte Liste aller lokalen IPs (`hostname -I` bzw. `Get-NetIPAddress`). Durch
  das Vorab-Registrieren aller IPs landen spätere Wazuh-/Shodan-Alerts auf einer
  dieser IPs beim selben Asset.
- `DRY_RUN=true` (optional)

## Install (Linux, systemd timer)

Mit dem Installer:

```bash
wget -O install.sh https://YOUR_SERVER/agent/latest/install.sh
sudo bash install.sh \
  --binary-url https://YOUR_SERVER/agent/latest/cve3po-agent-linux-amd64 \
  --sha256-url https://YOUR_SERVER/agent/latest/cve3po-agent-linux-amd64.sha256 \
  --api-url https://YOUR_CVE3PO/extensions/agent/inventory/ \
  --token YOUR_TOKEN
```

Danach:

```bash
sudo systemctl status cve3po-agent.timer
sudo systemctl list-timers --all | grep cve3po-agent
sudo journalctl -u cve3po-agent -n 100 --no-pager
```

Der Installer aktiviert einen `systemd` Timer mit **15 Minuten Intervall**.
