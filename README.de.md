# Sophos XGS Firewall für Home Assistant

🇬🇧 [English](README.md)

Custom Integration für Sophos-Firewalls mit SFOS (getestet mit **SFOS 22.0 GA**).
Sie nutzt **SNMP** für Systemwerte und die **XML-API** zum Lesen und Schalten von Firewall-Regeln.

## Was die Integration anlegt

**Sensoren**
- CPU-Auslastung, Arbeitsspeicher, Swap*, Festplatte (in %)
- Angemeldete Benutzer, letzter Neustart, Firmware, IPS-Signaturversion
- Lizenzstatus und Ablaufdatum je Modul (Base Firewall, Network, Web, Zero-Day, Support …)
- Tage bis zum nächsten Lizenzablauf
- Pro ausgewähltem Interface: Download/Upload in Mbit/s, Gesamtvolumen*
- Pro IPsec-Verbindung: Anzahl aktiver Tunnel*
- Pro Sophos Access Point: Anzahl Clients
- HA-Status (nur wenn ein HA-Cluster aktiv ist)

**Binäre Sensoren**
- Dienststatus (IPS, Antivirus, DNS, Web-Proxy, SSL-/IPsec-VPN, Gateway-Überwachung, NTP, SSH …)
- Link-Status pro ausgewähltem Interface (z. B. WAN-Port als „Internet-Leitung da?“)
- Verbindungsstatus pro IPsec-VPN
- Verbindungsstatus pro Access Point
- Lizenzproblem (abgelaufen/deaktiviert)
- HA-Cluster-Problem (nur bei HA)
- Erreichbarkeit von SNMP und API

**Schalter**
- Jede ausgewählte Firewall-Regel lässt sich aktivieren/deaktivieren

**Reparaturen**
- Warnung unter *Einstellungen → Reparaturen*, wenn eine Lizenz innerhalb von 30 Tagen abläuft (einstellbar, 0 = aus), und ein Fehler, wenn eine Lizenz abgelaufen ist

Neue IPsec-Verbindungen und Access Points werden automatisch ergänzt; entfernte werden als „nicht verfügbar“ angezeigt.

\* standardmäßig deaktiviert, kann unter *Entitäten* eingeschaltet werden.

Die Download-/Upload-Raten erscheinen ab dem zweiten Abruf (sie werden aus der Differenz der Zähler berechnet).

## Vorbereitung auf der Sophos

1. **Gerätezugriff** – *Administration → Gerätezugriff*: In der Zone, in der Home Assistant steht (meist LAN), **SNMP** und **HTTPS** (Webadmin) erlauben.
2. **SNMP** – *Administration → SNMP*:
   - SNMP-Agent aktivieren.
   - **v2c**: Community anlegen, als Manager-IP die IP von Home Assistant, *Queries* aktivieren.
   - oder **v3**: Benutzer anlegen (Authentifizierung SHA, Verschlüsselung AES empfohlen), Home-Assistant-IP eintragen.
3. **XML-API** – *Backup & Firmware → API*: API-Konfiguration aktivieren und unter *Zulässige IP-Adressen* die IP von Home Assistant eintragen.
4. **Admin-Benutzer** – Empfehlung: eigenen Administrator „homeassistant“ mit einem eigenen Profil anlegen, das **Firewall** mit Lese-/Schreibrecht und den Rest nur lesend erlaubt.

## Installation

**Manuell:** Den Ordner `custom_components/sophos_xgs` nach `/config/custom_components/` kopieren und Home Assistant neu starten.

**HACS:** In HACS → ⋮ → *Benutzerdefinierte Repositories* die URL `https://github.com/drened/ha-sophos-xgs` mit Typ *Integration* hinzufügen, „Sophos XGS Firewall“ installieren und Home Assistant neu starten.

Danach: *Einstellungen → Geräte & Dienste → Integration hinzufügen → „Sophos XGS Firewall“*.

Der Dialog fragt nacheinander:
1. Host, API-Benutzer/Passwort, Port (Standard 4444), SNMP-Version
2. SNMP-Community bzw. v3-Zugangsdaten
3. Welche Interfaces Sensoren bekommen (physische Ports sind vorausgewählt) und welche Firewall-Regeln als Schalter erscheinen sollen

Alles aus Schritt 3, die Abfrageintervalle (Standard: SNMP 30 s, API 60 s) und der Vorlauf der Lizenzwarnung (Standard 30 Tage) lassen sich später unter **Konfigurieren** ändern.

## Hinweise

- **Regel-Schalter ändern die Firewall-Konfiguration wirklich.** Jede Änderung erscheint im Admin-Log der Sophos. Keine Regel als Schalter anlegen, die den Zugriff von Home Assistant auf die Firewall selbst erlaubt.
- SFOS erwartet beim Ändern einer Regel die komplette Regel. Die Integration liest die Regel deshalb, ändert nur den Status und schreibt sie vollständig zurück. Bitte nach dem ersten Schalten in der Sophos-Oberfläche kontrollieren, dass die Regel ansonsten unverändert ist.
- Den Online-Status der Gateways gibt SFOS weder per SNMP noch per XML-API heraus. Für Ausfallmeldungen den Link-Sensor des WAN-Ports oder die *Ping*-Integration von Home Assistant nutzen.
- Das Lizenzablaufdatum wird aus dem Text der Firewall gelesen. Falls ein Format nicht erkannt wird, bleibt der Sensor „unbekannt“; der Originaltext steht im Attribut `rohwert`.
- Bei falschen API-Zugangsdaten startet Home Assistant automatisch eine Neuanmeldung.

## Beispiel-Automation

```yaml
automation:
  - alias: "Kinder: Internet um 21 Uhr aus"
    triggers:
      - trigger: time
        at: "21:00:00"
    actions:
      - action: switch.turn_on   # Regel "Kinder Internet" ist eine Drop-Regel
        target:
          entity_id: switch.xgs_home_regel_kinder_internet

  - alias: "WAN-Ausfall melden"
    triggers:
      - trigger: state
        entity_id: binary_sensor.xgs_home_port2_link
        to: "off"
        for: "00:01:00"
    actions:
      - action: notify.notify
        data:
          message: "Die WAN-Leitung der Sophos ist seit einer Minute down."
```

Die Entity-IDs hängen vom Gerätenamen und den Regel-/Interface-Namen ab.
