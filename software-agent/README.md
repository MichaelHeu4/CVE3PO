# CVE3PO Software Agent (Rust)

Der Agent sammelt installierte Software und sendet Snapshots an den CVE3PO Agent-Endpoint.

Für dpkg-Pakete meldet ein neu gebauter Agent zusätzlich Paketmanager, Debian-Quellpaket und Quellversion. CVE3PO kann damit Debian-Tracker-Versionen pro Host vergleichen. Alte Agent-Versionen bleiben kompatibel, liefern diese Informationen aber nicht; für den Abgleich den Agent neu bauen und auf den Hosts aktualisieren.

Der neue Agent kennzeichnet außerdem erfolgreich und vollständig erhobene dpkg- und RPM-Quellen sowie den Beginn des Snapshots. Erst zwei unterschiedliche, zeitlich aufeinanderfolgende vollständige Snapshots derselben Quelle können das Entfernen einer Installation bestätigen. Andere Quellen und ältere Agenten können weiterhin Inventar melden, lösen aber keine automatische Schließung aus. Fehlerhafte Erhebungen werden nicht als vollständige Snapshots versendet.

## Konfiguration

Der Agent liest Einstellungen in dieser Reihenfolge:
1. Environment Variablen
2. Datei aus `SOFTWARE_AGENT_CONFIG` (Default: `/etc/cve3po-agent/agent.env` unter Linux, `%ProgramData%\CVE3PO\agent.env` unter Windows)

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

## Installation unter Windows (64 Bit)

Das Docker-Image erstellt die Windows-EXE und stellt sie bei aktiviertem Agent-Modul unter `/agent/latest/cve3po-agent-windows-amd64.exe` samt `.sha256`-Datei bereit. Die Installationsseite der Anwendung enthält Befehle mit den URLs der jeweiligen Instanz. Alternativ erzeugt die GitHub Action **Build Windows software agent** das Artifact `cve3po-agent-windows-amd64` mit EXE, Prüfsumme und Beispielkonfiguration.

In einer PowerShell die Prüfsumme mit dem Inhalt der `.sha256`-Datei vergleichen und die Dateien einrichten:

```powershell
Get-FileHash .\cve3po-agent-windows-amd64.exe -Algorithm SHA256
Get-Content .\cve3po-agent-windows-amd64.exe.sha256
New-Item -ItemType Directory -Force "$env:ProgramData\CVE3PO"
Copy-Item .\cve3po-agent-windows-amd64.exe "$env:ProgramData\CVE3PO\"
Copy-Item .\agent.env.example "$env:ProgramData\CVE3PO\agent.env"
notepad "$env:ProgramData\CVE3PO\agent.env"
```

In `agent.env` mindestens `SOFTWARE_API_URL` und den Token setzen und die Datei als UTF-8 speichern. Den Zugriff auf die Konfiguration wegen des Tokens auf Administratoren und das ausführende Konto beschränken. Zum Testen:

```powershell
$env:DRY_RUN = 'true'
& "$env:ProgramData\CVE3PO\cve3po-agent-windows-amd64.exe"
Remove-Item Env:DRY_RUN
```

Für eine Ausführung alle 15 Minuten eine PowerShell **als Administrator** öffnen und eine geplante Aufgabe anlegen:

```powershell
$exe = "$env:ProgramData\CVE3PO\cve3po-agent-windows-amd64.exe"
$action = New-ScheduledTaskAction -Execute $exe
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName 'CVE3PO Agent' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest
Start-ScheduledTask -TaskName 'CVE3PO Agent'
Get-ScheduledTaskInfo -TaskName 'CVE3PO Agent'
```

Der Agent erfasst Programme aus den Windows-Uninstall-Registry-Schlüsseln mit Anzeigename und Version. Bei Ausführung als SYSTEM betrifft der benutzerspezifische Schlüssel das SYSTEM-Konto; Programme anderer Benutzer werden darüber nicht vollständig erfasst. Windows-Inventar bestätigt derzeit keine automatischen Entfernungen.
