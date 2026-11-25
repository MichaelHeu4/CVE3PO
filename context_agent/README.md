# CVE3PO Context-Agent (Pilot)

Dies ist ein separater Python-Dienst. Er ersetzt weder den bestehenden Rust-Agenten noch dessen Binary, Konfiguration, systemd-Timer, Windows-Aufgabe, Download-Adressen oder Ansible-Rollout. Für den Pilot nur explizit ausgewählte Hosts einrichten. Voraussetzung sind Python 3, osquery und eine über HTTPS erreichbare CVE3PO-Instanz. Der Server benötigt die aktuellen Migrationen. Der Agent ist bewusst kein Ersatz für das bisherige Agent-Binary.

## Host registrieren

Auf dem CVE3PO-Server `python manage.py register_context_agent HOST_ID` ausführen. Die ausgegebene zufällige Kennung wird nur einmal angezeigt. Sie gehört genau zu diesem Host; auf dem Server liegt nur ein Hash. Mit `--rotate` kann die Kennung widerrufen und neu ausgestellt werden. Keine Kennung in Versionsverwaltung oder Ansible-Ausgaben übernehmen. Zugriffe auf die Konfiguration auf das Dienstkonto und Administratoren beschränken. Bei Kompromittierung den Agenten deaktivieren oder die Kennung rotieren.

Das separate Pilot-ZIP ist für Staff-Nutzer auf der Host-Seite und unter `/context-agent/pilot.zip` verfügbar. Den Inhalt separat auf den Testhost kopieren. `config.example.json` als separate Konfigurationsdatei anlegen und `server_url`, `token`, `osquery_path`, `legacy_agent_path` und ggf. `legacy_agent_config` anpassen. HTTPS muss ein vom Python-Systemzertifikatsspeicher vertrauenswürdiges Zertifikat verwenden. Der Legacy-Agent wird nur mit `DRY_RUN=true` gestartet; dessen JSON wird als eigener Pilot-Snapshot gespeichert und **nicht** in den bisherigen Inventarabgleich eingespeist. Daher können durch diese Aufträge keine Findings geschlossen werden. Fehlender Legacy-Agent oder fehlende Konfiguration führt zu einem sichtbaren Fehler. Inventar kann Namen und Versionen enthalten und ist in der Hostansicht sichtbar.

## Linux

Das separate Verzeichnis nach `/opt/cve3po-context-agent` kopieren und die eigene Konfiguration als `/etc/cve3po-context-agent/config.json` ablegen. Die enthaltene `cve3po-context-agent.service` unter diesem Namen in systemd installieren und aktivieren. Der Dienst liest die Konfiguration automatisch und startet unabhängig vom alten Timer. Dienstkonto, Leserechte und osquery-Rechte müssen für die gewählten Prüfungen passen; fehlende Rechte sind kein Nachweis für Abwesenheit.

## Windows

Einen eigenen Python-3-Runtime mit pywin32 installieren. Das Agentenverzeichnis beispielsweise unter `C:\Program Files\CVE3PO-Context` und die separate Konfiguration unter `%ProgramData%\CVE3PO-Context\config.json` ablegen. Absolute Windows-Pfade in JSON mit doppeltem Backslash schreiben. In einer administrativen PowerShell aus dem Agentenverzeichnis mit dem **zugehörigen Python** ausführen:

```
python windows_service.py --startup auto install
python windows_service.py start
```

Der eigene Dienst heißt `CVE3POContextAgent`. Zum Entfernen `python windows_service.py stop` und `python windows_service.py remove` im selben Verzeichnis ausführen. Die bisherige Aufgabe bleibt bestehen.

Optional begrenzt `windows_cpus`, z. B. `[8, 9]`, den Dienstprozess auf diese **logischen Prozessoren innerhalb seiner primären Prozessorgruppe**; Kindprozesse erben die Prozessaffinität. Unzulässige CPUs verhindern den Dienststart. Auf Systemen mit mehreren Prozessorgruppen unterstützt diese Pilotversion keine Auswahl außerhalb der primären Gruppe. Die Zuordnung und die Affinität von Dienst und osquery müssen auf dem konkreten Windows-Testhost geprüft werden, bevor reservierte CPUs als geschützt gelten.

## Betrieb und Grenzen

Der Agent fragt standardmäßig alle 60 Sekunden über eine ausgehende Verbindung nach Aufträgen. Beim Kontakt veranlasst der Server maximal stündlich einen separaten Inventarauftrag. Offline-Hosts erhalten bei ihrem nächsten Kontakt einen neuen Auftrag. Ein Auftrag ist eine Stunde gültig; eine Ausführungszusage ist fünf Minuten gültig und ihr Ergebnis kann nur einmal abgegeben werden. Alte Zusagen werden bei Wiederholung ungültig. Der Host zeigt Kontakt, Fähigkeiten und die letzten Inventaraufträge.

Eine berechtigte Person muss eine KI-Abfrage ausdrücklich freigeben. Server und Agent akzeptieren nur das gemeinsame Regelwerk in `policy.py`: einen einzelnen SELECT mit expliziten erlaubten Spalten, bis zu fünf AND-verknüpften Filtern und LIMIT bis 100. Neben Prozessen, Diensten, Paketen und Ports sind unter anderem systemd-Units, geladene Prozessdateien, Dateimetadaten sowie eingeschränkt sysctl- und Schannel-Registry-Werte abfragbar. Dateipfade und bestimmte Konfigurationsschlüssel müssen exakt angegeben werden. Keine Joins, Dateiinhalte, Shell-Kommandos oder freien SQL-Ausdrücke. Die Ausführung ist zeitlich und hinsichtlich der Ausgabe begrenzt. Nicht unterstützte Konfigurationsprüfungen bleiben manuell zu klären. Leere Ergebnisse werden nicht automatisch als Gegenbeleg gewertet. Fehlende osquery-Tabellen oder Rechte, Fehler und Zeitüberschreitung führen zu keinem positiven oder negativen Befund. Nach einer Erweiterung dieser Regeln muss das separate Pilotpaket auf den Testhosts aktualisiert werden; ein älterer Context-Agent lehnt ihm unbekannte Abfragen ab.

### Konfigurationsprüfungen mit Augeas

Der Agent benötigt eine Linux-osquery-Installation mit verfügbarer `augeas`-Tabelle und passenden Augeas-Lenses. Nicht jede Installation enthält diese Tabelle oder Lenses. Das Dienstkonto benötigt Leserechte auf die ausgewählten Dateien; ein leeres oder fehlgeschlagenes Ergebnis belegt nicht, dass eine Einstellung fehlt.

Für beliebige Programme sind einzelne Augeas-Abfragen nach ausdrücklicher Freigabe möglich. Dafür in der Agent-Konfiguration `augeas_allowed_roots` auf die explizit freigegebenen Verzeichnisse und `augeas_allowed_labels` auf die explizit freigegebenen Feldnamen setzen, beispielsweise `["/etc/ssh"]` und `["PermitRootLogin"]`. Beide Listen sind standardmäßig leer. Die Abfrage muss einen exakten Dateipfad und einen exakten Label-Namen verwenden; der Agent überprüft den realen Dateipfad und den Label-Namen lokal erneut. Die jeweiligen Lenses müssen das konkrete Format und den Label-Namen unterstützen. Freigegebene Werte und Dateipfade werden auf den Server übertragen; Zugangsdaten oder andere geheime Felder nicht freigeben.

Für Apache gibt es zusätzlich eine allgemeine, nicht an eine CVE gebundene Prüfung über den Button in einer Kontextbewertung. Auf dem Agenten `apache_server_root`, `apache_config_path` und `apache_allowed_roots` setzen, z. B. `/etc/apache2`, `/etc/apache2/apache2.conf` und `["/etc/apache2"]`. Der Agent fragt die konfigurierten Dateien mit Augeas ab, folgt erreichbaren `Include`- und `IncludeOptional`-Einträgen innerhalb der erlaubten Verzeichnisse und zeigt ausgewählte Direktiven sowie Virtual Hosts an. Die Prüfung ist auf Dateien, Laufzeit und Ergebnisumfang begrenzt und überträgt nur ausgewählte Direktiven. Lenses, Apache-Variablen, Bedingungen, Symlinks außerhalb erlaubter Verzeichnisse, wiederholte Includes, ungewöhnliche Konfigurationen und fehlende Rechte können die Auswertung unvollständig machen. Warnungen und die untersuchten Dateien werden angezeigt; die effektive Apache-Konfiguration, vollständige Erreichbarkeit und CVE-Betroffenheit werden nicht automatisch bestätigt. Insbesondere ersetzt das Ergebnis nicht die Prüfung von Includes, Vererbung und laufender Konfiguration durch eine Fachperson.

Im Finding werden Ergebnisse und Freigaben pro Host angezeigt. Die manuelle Bewertung verlangt eine Begründung; nach 24 Stunden oder bei Änderung des gespeicherten Software-/OS-Ziels wird sie als veraltet angezeigt. Konfigurationsänderungen können auch innerhalb dieser Frist auftreten: Im Zweifel erneut prüfen. Bei der Erstellung eines neuen KI-Vorschlags werden neben CVE und CTI auch bis zu je 100 Prozess- und Portbeobachtungen des letzten zugeordneten Wazuh-Snapshots an den konfigurierten KI-Anbieter übertragen. Diese können sensible Informationen enthalten; Zugriff und Datenweitergabe entsprechend festlegen.
