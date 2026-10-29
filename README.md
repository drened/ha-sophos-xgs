# Sophos XGS Firewall for Home Assistant

[![hacs][hacs-badge]][hacs-url]
[![Validate](https://github.com/drened/ha-sophos-xgs/actions/workflows/validate.yml/badge.svg)](https://github.com/drened/ha-sophos-xgs/actions/workflows/validate.yml)

🇩🇪 [Deutsche Anleitung](README.de.md)

Custom integration for Sophos firewalls running **SFOS** (XGS and virtual/software appliances).
It reads system data via **SNMP** and uses the **XML API** to read and toggle firewall rules.

Tested with **SFOS 22.0 GA**.

## Features

**Sensors**
- CPU, memory, swap*, disk usage (%)
- Logged-in users, last boot, firmware, IPS signature version
- License status and expiry date per module (Base Firewall, Network, Web, Zero-Day, Support …)
- Per selected interface: download/upload in Mbit/s, total traffic*
- Per IPsec connection: number of active tunnels*
- Per Sophos access point: number of clients
- HA status (only when an HA cluster is active)

**Binary sensors**
- Service status (IPS, antivirus, DNS, web proxy, SSL/IPsec VPN, gateway monitoring, NTP, SSH …)
- Link state per selected interface (e.g. WAN port as "internet line up")
- Connection state per IPsec VPN and per access point
- License problem (expired/deactivated)
- HA cluster problem (HA only)
- SNMP and API reachability

**Switches**
- Each selected firewall rule can be enabled/disabled

\* disabled by default, enable under *Entities*.

Download/upload rates are counted from the firewall port's point of view and appear from the second poll on.

## Installation

### HACS

1. HACS → ⋮ → **Custom repositories**
2. Repository: `https://github.com/drened/ha-sophos-xgs`, type: **Integration**
3. Install **Sophos XGS Firewall** and restart Home Assistant

### Manual

Copy `custom_components/sophos_xgs` to `/config/custom_components/` and restart Home Assistant.

## Preparing the firewall

1. **Device access** – *Administration → Device access*: allow **SNMP** and **HTTPS** for the zone Home Assistant lives in (usually LAN).
2. **SNMP** – *Administration → SNMP*: enable the agent and create a v2c community or a v3 user with the Home Assistant IP as manager.
3. **XML API** – *Backup & firmware → API*: enable the API and add the Home Assistant IP to the allowed IP addresses.
4. **Admin user** – recommended: a dedicated administrator with a profile that has write access to *Firewall* and read-only access to everything else.

## Setup

*Settings → Devices & services → Add integration → "Sophos XGS Firewall"*

1. Host, API user/password, port (default 4444), SNMP version
2. SNMP community or v3 credentials
3. Interfaces that get sensors (physical ports are preselected) and firewall rules to expose as switches

Interfaces, rules and polling intervals (default SNMP 30 s, API 60 s) can be changed later via **Configure**.

## Notes

- **Rule switches really change the firewall configuration.** Every change shows up in the Sophos admin log. Do not expose a rule that Home Assistant itself needs to reach the firewall.
- SFOS requires the complete rule when updating it. The integration reads the rule, changes only its status and writes it back in full.
- New IPsec connections or access points are picked up on the next reload of the integration.
- If a license expiry format is not recognized, the sensor stays *unknown*; the original text is in the `rohwert` attribute. Please open an issue with that value.

## Example automations

```yaml
automation:
  - alias: "Kids: internet off at 9 pm"
    triggers:
      - trigger: time
        at: "21:00:00"
    actions:
      - action: switch.turn_on   # "Kids internet" is a drop rule
        target:
          entity_id: switch.xgs_regel_kids_internet

  - alias: "Notify on WAN outage"
    triggers:
      - trigger: state
        entity_id: binary_sensor.xgs_port2_link
        to: "off"
        for: "00:01:00"
    actions:
      - action: notify.notify
        data:
          message: "The Sophos WAN line has been down for one minute."
```

Entity IDs depend on device, rule and interface names.

## Disclaimer

This is a community project and not affiliated with or endorsed by Sophos Ltd.

[hacs-badge]: https://img.shields.io/badge/HACS-Custom-41BDF5.svg
[hacs-url]: https://hacs.xyz/docs/faq/custom_repositories
