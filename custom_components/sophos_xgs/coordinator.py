"""Datenabruf (SNMP und XML-API) für die Sophos-XGS-Integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
import logging
import time
from typing import TYPE_CHECKING, Any

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import (
    FirewallRule,
    SophosApiAccessDenied,
    SophosApiAuthError,
    SophosApiClient,
    SophosApiError,
)
from .const import (
    CONF_API_INTERVAL,
    CONF_LICENSE_WARN_DAYS,
    CONF_SNMP_INTERVAL,
    DEFAULT_API_INTERVAL,
    DEFAULT_LICENSE_WARN_DAYS,
    DEFAULT_SNMP_INTERVAL,
    DOMAIN,
    LICENSE_ACTIVE_STATES,
    LICENSE_STATES,
    LICENSES,
    OID_AP_CLIENTS,
    OID_AP_MODEL,
    OID_AP_NAME,
    OID_AP_STATUS,
    OID_HR_PROCESSOR_LOAD,
    OID_IF_ALIAS,
    OID_IF_HC_IN,
    OID_IF_HC_OUT,
    OID_IF_HIGH_SPEED,
    OID_IF_NAME,
    OID_IF_OPER_STATUS,
    OID_IPSEC_ACTIVATED,
    OID_IPSEC_ACTIVE_TUNNELS,
    OID_IPSEC_NAME,
    OID_IPSEC_STATUS,
    SCALAR_OIDS,
    SERVICES,
    SFOS,
)
from .snmp import SnmpError, SophosSnmpClient

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

_LICENSE_DATE_FORMATS = (
    "%b %d %Y",
    "%d %b %Y",
    "%b %d, %Y",
    "%d-%b-%Y",
    "%Y-%m-%d",
    "%d.%m.%Y",
    "%m/%d/%Y",
    "%Y/%m/%d",
)


def parse_license_date(raw: str | None) -> datetime | None:
    """Ablaufdatum aus SFOS in ein date-Objekt umwandeln."""
    if not raw:
        return None
    text = " ".join(raw.split())
    for fmt in _LICENSE_DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


# SFOS Home und Dauerlizenzen melden als Ablaufdatum z. B. "Dec 31 2999".
# Alles, was weiter als 50 Jahre in der Zukunft liegt, gilt als unbegrenzt.
PERPETUAL_DAYS = 365 * 50


def license_expiries(data: SnmpData) -> list[tuple[str, str, int, date]]:
    """Laufende, befristete Lizenzen: (key, Name, Resttage, Datum), sortiert."""
    today = dt_util.now().date()
    result: list[tuple[str, str, int, date]] = []
    for key, (status, raw) in data.licenses.items():
        if LICENSE_STATES.get(status) not in LICENSE_ACTIVE_STATES:
            continue
        parsed = parse_license_date(raw)
        if parsed is None:
            continue
        expiry = parsed.date()
        days = (expiry - today).days
        if days > PERPETUAL_DAYS:
            continue
        result.append((key, LICENSES[key][1], days, expiry))
    result.sort(key=lambda item: item[2])
    return result


def next_license_expiry(data: SnmpData) -> tuple[str, str, int, date] | None:
    """Die als Nächstes ablaufende Lizenz."""
    expiries = license_expiries(data)
    return expiries[0] if expiries else None


@dataclass(slots=True)
class InterfaceData:
    """Werte eines Netzwerk-Interfaces."""

    name: str
    alias: str | None = None
    up: bool | None = None
    speed_mbit: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_mbit: float | None = None
    tx_mbit: float | None = None


@dataclass(slots=True)
class TunnelData:
    """IPsec-Verbindung."""

    name: str
    status: int | None = None  # 0 inaktiv, 1 aktiv, 2 teilweise aktiv
    activated: int | None = None
    active_tunnels: int | None = None


@dataclass(slots=True)
class AccessPointData:
    """Sophos Access Point."""

    name: str
    model: str | None = None
    connected: bool | None = None
    clients: int | None = None


@dataclass(slots=True)
class SnmpData:
    """Gesamtergebnis eines SNMP-Abrufs."""

    scalars: dict[str, Any] = field(default_factory=dict)
    cpu: float | None = None
    boot_time: datetime | None = None
    services: dict[str, int | None] = field(default_factory=dict)
    licenses: dict[str, tuple[int | None, str | None]] = field(default_factory=dict)
    interfaces: dict[str, InterfaceData] = field(default_factory=dict)
    tunnels: dict[str, TunnelData] = field(default_factory=dict)
    access_points: dict[str, AccessPointData] = field(default_factory=dict)


def _service_oids() -> dict[str, str]:
    return {f"svc_{key}": f"{SFOS}.3.{idx}.0" for key, (idx, _, _) in SERVICES.items()}


def _license_oids() -> dict[str, str]:
    oids: dict[str, str] = {}
    for key, (idx, _, _) in LICENSES.items():
        oids[f"lic_{key}_status"] = f"{SFOS}.5.{idx}.1.0"
        oids[f"lic_{key}_expiry"] = f"{SFOS}.5.{idx}.2.0"
    return oids


class SophosSnmpCoordinator(DataUpdateCoordinator[SnmpData]):
    """Fragt Systemwerte per SNMP ab."""

    config_entry: ConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: SophosSnmpClient
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} SNMP",
            update_interval=timedelta(
                seconds=entry.options.get(CONF_SNMP_INTERVAL, DEFAULT_SNMP_INTERVAL)
            ),
        )
        self.client = client
        self._all_oids = {**SCALAR_OIDS, **_service_oids(), **_license_oids()}
        self._prev_counters: dict[str, tuple[float, int | None, int | None]] = {}
        self._boot_time: datetime | None = None

    async def _async_update_data(self) -> SnmpData:
        try:
            data = await self._fetch()
        except SnmpError as err:
            raise UpdateFailed(f"SNMP-Abfrage fehlgeschlagen: {err}") from err
        self._update_license_issues(data)
        return data

    def _update_license_issues(self, data: SnmpData) -> None:
        """Hinweise unter Einstellungen → Reparaturen pflegen."""
        warn_days = int(
            self.config_entry.options.get(
                CONF_LICENSE_WARN_DAYS, DEFAULT_LICENSE_WARN_DAYS
            )
        )
        title = self.config_entry.title
        expiring = {
            key: (name, days, expiry)
            for key, name, days, expiry in license_expiries(data)
            if warn_days > 0 and days <= warn_days
        }
        expired = {
            key
            for key, (status, _) in data.licenses.items()
            if LICENSE_STATES.get(status) == "expired"
        }
        entry_id = self.config_entry.entry_id
        for key, (_, name, _) in LICENSES.items():
            expiring_id = f"{entry_id}_license_expiring_{key}"
            expired_id = f"{entry_id}_license_expired_{key}"
            if key in expiring:
                _, days, expiry = expiring[key]
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    expiring_id,
                    is_fixable=False,
                    is_persistent=False,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key="license_expiring",
                    translation_placeholders={
                        "firewall": title,
                        "license": name,
                        "days": str(max(days, 0)),
                        "date": expiry.strftime("%d.%m.%Y"),
                    },
                )
            else:
                ir.async_delete_issue(self.hass, DOMAIN, expiring_id)
            if key in expired:
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    expired_id,
                    is_fixable=False,
                    is_persistent=False,
                    severity=ir.IssueSeverity.ERROR,
                    translation_key="license_expired",
                    translation_placeholders={"firewall": title, "license": name},
                )
            else:
                ir.async_delete_issue(self.hass, DOMAIN, expired_id)

    async def _fetch(self) -> SnmpData:
        raw = await self.client.async_get(self._all_oids)
        if raw.get("device_name") is None and raw.get("fw_version") is None:
            raise SnmpError("Keine SFOS-Daten erhalten – SNMP-Zugriff prüfen")

        data = SnmpData()
        data.scalars = {k: raw.get(k) for k in SCALAR_OIDS}
        data.services = {key: raw.get(f"svc_{key}") for key in SERVICES}
        data.licenses = {
            key: (raw.get(f"lic_{key}_status"), raw.get(f"lic_{key}_expiry"))
            for key in LICENSES
        }

        # CPU: zuerst UCD ssCpuIdle, sonst Mittelwert aus hrProcessorLoad
        idle = raw.get("cpu_idle")
        if isinstance(idle, int):
            data.cpu = float(max(0, min(100, 100 - idle)))
        else:
            try:
                loads = [
                    v for v in (await self.client.async_walk(OID_HR_PROCESSOR_LOAD)).values()
                    if isinstance(v, int)
                ]
            except SnmpError:
                loads = []
            if loads:
                data.cpu = round(sum(loads) / len(loads), 1)

        # Bootzeitpunkt aus Uptime (TimeTicks = 1/100 s), stabilisiert
        uptime = raw.get("uptime")
        if isinstance(uptime, int):
            boot = dt_util.utcnow() - timedelta(seconds=uptime / 100)
            boot = boot.replace(second=0, microsecond=0)
            if self._boot_time is None or abs(
                (boot - self._boot_time).total_seconds()
            ) > 120:
                self._boot_time = boot
            data.boot_time = self._boot_time

        data.interfaces = await self._fetch_interfaces()
        data.tunnels = await self._fetch_tunnels()
        data.access_points = await self._fetch_access_points()
        return data

    async def _fetch_interfaces(self) -> dict[str, InterfaceData]:
        names = await self.client.async_walk(OID_IF_NAME)
        if not names:
            return {}
        oper = await self.client.async_walk(OID_IF_OPER_STATUS)
        rx = await self.client.async_walk(OID_IF_HC_IN)
        tx = await self.client.async_walk(OID_IF_HC_OUT)
        try:
            alias = await self.client.async_walk(OID_IF_ALIAS)
            speed = await self.client.async_walk(OID_IF_HIGH_SPEED)
        except SnmpError:
            alias, speed = {}, {}

        now = time.monotonic()
        result: dict[str, InterfaceData] = {}
        for idx, name in names.items():
            if not isinstance(name, str) or not name:
                continue
            ifd = InterfaceData(
                name=name,
                alias=alias.get(idx) or None,
                up=(oper.get(idx) == 1) if idx in oper else None,
                speed_mbit=speed.get(idx) if isinstance(speed.get(idx), int) else None,
                rx_bytes=rx.get(idx) if isinstance(rx.get(idx), int) else None,
                tx_bytes=tx.get(idx) if isinstance(tx.get(idx), int) else None,
            )
            prev = self._prev_counters.get(name)
            if prev is not None:
                p_time, p_rx, p_tx = prev
                dt = now - p_time
                if dt > 0:
                    if ifd.rx_bytes is not None and p_rx is not None and ifd.rx_bytes >= p_rx:
                        ifd.rx_mbit = round((ifd.rx_bytes - p_rx) * 8 / dt / 1_000_000, 3)
                    if ifd.tx_bytes is not None and p_tx is not None and ifd.tx_bytes >= p_tx:
                        ifd.tx_mbit = round((ifd.tx_bytes - p_tx) * 8 / dt / 1_000_000, 3)
            self._prev_counters[name] = (now, ifd.rx_bytes, ifd.tx_bytes)
            result[name] = ifd
        return result

    async def _fetch_tunnels(self) -> dict[str, TunnelData]:
        try:
            names = await self.client.async_walk(OID_IPSEC_NAME)
            if not names:
                return {}
            status = await self.client.async_walk(OID_IPSEC_STATUS)
            activated = await self.client.async_walk(OID_IPSEC_ACTIVATED)
            active = await self.client.async_walk(OID_IPSEC_ACTIVE_TUNNELS)
        except SnmpError as err:
            _LOGGER.debug("IPsec-Tabelle nicht lesbar: %s", err)
            return {}
        return {
            name: TunnelData(
                name=name,
                status=status.get(idx),
                activated=activated.get(idx),
                active_tunnels=active.get(idx),
            )
            for idx, name in names.items()
            if isinstance(name, str) and name
        }

    async def _fetch_access_points(self) -> dict[str, AccessPointData]:
        try:
            names = await self.client.async_walk(OID_AP_NAME)
            if not names:
                return {}
            model = await self.client.async_walk(OID_AP_MODEL)
            status = await self.client.async_walk(OID_AP_STATUS)
            clients = await self.client.async_walk(OID_AP_CLIENTS)
        except SnmpError as err:
            _LOGGER.debug("AP-Tabelle nicht lesbar: %s", err)
            return {}
        return {
            name: AccessPointData(
                name=name,
                model=model.get(idx) or None,
                connected=(status.get(idx) == 0) if idx in status else None,
                clients=clients.get(idx) if isinstance(clients.get(idx), int) else None,
            )
            for idx, name in names.items()
            if isinstance(name, str) and name
        }


class SophosApiCoordinator(DataUpdateCoordinator[dict[str, FirewallRule]]):
    """Liest die Firewall-Regeln per XML-API."""

    config_entry: ConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: SophosApiClient
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} API",
            update_interval=timedelta(
                seconds=entry.options.get(CONF_API_INTERVAL, DEFAULT_API_INTERVAL)
            ),
        )
        self.client = client

    async def _async_update_data(self) -> dict[str, FirewallRule]:
        try:
            return await self.client.async_get_firewall_rules()
        except SophosApiAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except SophosApiAccessDenied as err:
            raise UpdateFailed(
                f"API-Zugriff verweigert (API aktiviert, HA-IP freigegeben?): {err}"
            ) from err
        except SophosApiError as err:
            raise UpdateFailed(f"XML-API-Abfrage fehlgeschlagen: {err}") from err
