"""Konstanten für die Sophos-XGS-Integration."""

from __future__ import annotations

DOMAIN = "sophos_xgs"
MANUFACTURER = "Sophos"

# Konfiguration
CONF_API_PORT = "api_port"
CONF_VERIFY_SSL = "verify_ssl"
CONF_SNMP_PORT = "snmp_port"
CONF_SNMP_VERSION = "snmp_version"
CONF_COMMUNITY = "community"
CONF_V3_USER = "v3_user"
CONF_V3_AUTH_PROTO = "v3_auth_protocol"
CONF_V3_AUTH_KEY = "v3_auth_key"
CONF_V3_PRIV_PROTO = "v3_priv_protocol"
CONF_V3_PRIV_KEY = "v3_priv_key"

# Optionen
CONF_INTERFACES = "interfaces"
CONF_RULES = "firewall_rules"
CONF_SNMP_INTERVAL = "snmp_interval"
CONF_API_INTERVAL = "api_interval"
CONF_LICENSE_WARN_DAYS = "license_warn_days"

DEFAULT_API_PORT = 4444
DEFAULT_SNMP_PORT = 161
DEFAULT_SNMP_INTERVAL = 30
DEFAULT_API_INTERVAL = 60
DEFAULT_LICENSE_WARN_DAYS = 30

SNMP_V2C = "v2c"
SNMP_V3 = "v3"

AUTH_PROTOCOLS = ["none", "MD5", "SHA", "SHA256", "SHA512"]
PRIV_PROTOCOLS = ["none", "DES", "AES", "AES256"]

# ---------------------------------------------------------------------------
# SFOS-FIREWALL-MIB (Basis 1.3.6.1.4.1.2604.5.1)
# ---------------------------------------------------------------------------
SFOS = "1.3.6.1.4.1.2604.5.1"

SCALAR_OIDS: dict[str, str] = {
    "device_name": f"{SFOS}.1.1.0",
    "device_type": f"{SFOS}.1.2.0",
    "fw_version": f"{SFOS}.1.3.0",
    "app_key": f"{SFOS}.1.4.0",
    "webcat_version": f"{SFOS}.1.5.0",
    "ips_version": f"{SFOS}.1.6.0",
    "uptime": f"{SFOS}.2.2.0",
    "disk_capacity": f"{SFOS}.2.4.1.0",
    "disk_percent": f"{SFOS}.2.4.2.0",
    "mem_capacity": f"{SFOS}.2.5.1.0",
    "mem_percent": f"{SFOS}.2.5.2.0",
    "swap_capacity": f"{SFOS}.2.5.3.0",
    "swap_percent": f"{SFOS}.2.5.4.0",
    "live_users": f"{SFOS}.2.6.0",
    "http_hits": f"{SFOS}.2.7.0",
    "ha_status": f"{SFOS}.4.1.0",
    "ha_state": f"{SFOS}.4.4.0",
    "ha_peer_state": f"{SFOS}.4.5.0",
    # UCD-SNMP-MIB ssCpuIdle (Net-SNMP), Fallback siehe HOST-RESOURCES
    "cpu_idle": "1.3.6.1.4.1.2021.11.11.0",
}

# HOST-RESOURCES-MIB hrProcessorLoad (Fallback für CPU)
OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"

# Dienste: key -> (Index unter .3, Anzeigename, standardmäßig aktiviert)
SERVICES: dict[str, tuple[int, str, bool]] = {
    "pop3": (1, "POP3", False),
    "imap4": (2, "IMAP4", False),
    "smtp": (3, "SMTP", False),
    "ftp": (4, "FTP", False),
    "http": (5, "Web-Proxy", True),
    "av": (6, "Antivirus", True),
    "antispam": (7, "Anti-Spam", False),
    "dns": (8, "DNS", True),
    "ha": (9, "HA", False),
    "ips": (10, "IPS", True),
    "apache": (11, "Apache", False),
    "ntp": (12, "NTP", True),
    "tomcat": (13, "Tomcat", False),
    "sslvpn": (14, "SSL-VPN", True),
    "ipsec": (15, "IPsec-VPN", True),
    "database": (16, "Datenbank", False),
    "network": (17, "Netzwerk", True),
    "garner": (18, "Logging (Garner)", True),
    "drouting": (19, "Dynamisches Routing", False),
    "sshd": (20, "SSH", True),
    "dgd": (21, "Gateway-Überwachung", True),
}
SERVICE_STATES = {
    0: "untouched",
    1: "stopped",
    2: "initializing",
    3: "running",
    4: "exiting",
    5: "dead",
    6: "frozen",
    7: "unregistered",
}
SERVICE_RUNNING = 3

# Lizenzen: key -> (Index unter .5, Anzeigename, standardmäßig aktiviert)
LICENSES: dict[str, tuple[int, str, bool]] = {
    "base_fw": (1, "Base Firewall", True),
    "network": (2, "Network Protection", True),
    "web": (3, "Web Protection", True),
    "mail": (4, "Email Protection", False),
    "webserver": (5, "Webserver Protection", False),
    "sandstorm": (6, "Zero-Day Protection", True),
    "enhanced_support": (7, "Enhanced Support", True),
    "enhanced_plus": (8, "Enhanced Plus Support", False),
    "central_orchestration": (9, "Central Orchestration", False),
}
LICENSE_STATES = {
    0: "none",
    1: "evaluating",
    2: "notsubscribed",
    3: "subscribed",
    4: "expired",
    5: "deactivated",
}
LICENSE_PROBLEM_STATES = {"expired", "deactivated"}
# Lizenzen mit diesen Zuständen laufen (noch) und haben ein relevantes Ablaufdatum
LICENSE_ACTIVE_STATES = {"subscribed", "evaluating"}

HA_STATES = {
    0: "notapplicable",
    1: "auxiliary",
    2: "standalone",
    3: "primary",
    4: "faulty",
    5: "ready",
}

# IPsec-Tunneltabelle
OID_IPSEC_NAME = f"{SFOS}.6.1.1.1.1.2"
OID_IPSEC_ACTIVE_TUNNELS = f"{SFOS}.6.1.1.1.1.8"
OID_IPSEC_STATUS = f"{SFOS}.6.1.1.1.1.9"  # 0 inaktiv, 1 aktiv, 2 teilweise
OID_IPSEC_ACTIVATED = f"{SFOS}.6.1.1.1.1.10"  # 0 deaktiviert, 1 aktiviert

# Access Points (Sophos Wireless)
OID_AP_NAME = f"{SFOS}.7.1.1.1"
OID_AP_MODEL = f"{SFOS}.7.1.1.2"
OID_AP_STATUS = f"{SFOS}.7.1.1.5"  # 0 verbunden, 1 getrennt
OID_AP_CLIENTS = f"{SFOS}.7.1.1.6"

# IF-MIB
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
