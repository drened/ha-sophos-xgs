"""Sensoren der Sophos-XGS-Integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from typing import TYPE_CHECKING, Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfDataRate,
    UnitOfInformation,
)

from .const import CONF_INTERFACES, HA_STATES, LICENSE_STATES, LICENSES
from .coordinator import SnmpData, SophosSnmpCoordinator, parse_license_date
from .entity import SophosEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from . import SophosConfigEntry

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class SophosSensorDescription(SensorEntityDescription):
    """Beschreibung eines SNMP-Sensors."""

    value_fn: Callable[[SnmpData], Any]
    attr_fn: Callable[[SnmpData], dict[str, Any] | None] | None = None


def _scalar(key: str) -> Callable[[SnmpData], Any]:
    return lambda d: d.scalars.get(key)


SYSTEM_SENSORS: tuple[SophosSensorDescription, ...] = (
    SophosSensorDescription(
        key="cpu",
        name="CPU-Auslastung",
        icon="mdi:cpu-64-bit",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.cpu,
    ),
    SophosSensorDescription(
        key="memory",
        name="Arbeitsspeicher",
        icon="mdi:memory",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_scalar("mem_percent"),
        attr_fn=lambda d: {"kapazitaet_mb": d.scalars.get("mem_capacity")},
    ),
    SophosSensorDescription(
        key="swap",
        name="Swap",
        icon="mdi:swap-horizontal",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=_scalar("swap_percent"),
    ),
    SophosSensorDescription(
        key="disk",
        name="Festplatte",
        icon="mdi:harddisk",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_scalar("disk_percent"),
        attr_fn=lambda d: {"kapazitaet_mb": d.scalars.get("disk_capacity")},
    ),
    SophosSensorDescription(
        key="live_users",
        name="Angemeldete Benutzer",
        icon="mdi:account-multiple",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_scalar("live_users"),
    ),
    SophosSensorDescription(
        key="boot_time",
        name="Letzter Neustart",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.boot_time,
    ),
    SophosSensorDescription(
        key="firmware",
        name="Firmware",
        icon="mdi:package-variant",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_scalar("fw_version"),
    ),
    SophosSensorDescription(
        key="ips_version",
        name="IPS-Signaturen",
        icon="mdi:shield-search",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_scalar("ips_version"),
    ),
    SophosSensorDescription(
        key="webcat_version",
        name="Webkategorien-Version",
        icon="mdi:web",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=_scalar("webcat_version"),
    ),
    SophosSensorDescription(
        key="http_hits",
        name="HTTP-Anfragen",
        icon="mdi:counter",
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_registry_enabled_default=False,
        value_fn=_scalar("http_hits"),
    ),
)

HA_SENSORS: tuple[SophosSensorDescription, ...] = (
    SophosSensorDescription(
        key="ha_state",
        name="HA-Status",
        icon="mdi:server-network",
        device_class=SensorDeviceClass.ENUM,
        options=list(HA_STATES.values()),
        value_fn=lambda d: HA_STATES.get(d.scalars.get("ha_state")),
    ),
    SophosSensorDescription(
        key="ha_peer_state",
        name="HA-Status Partner",
        icon="mdi:server-network",
        device_class=SensorDeviceClass.ENUM,
        options=list(HA_STATES.values()),
        value_fn=lambda d: HA_STATES.get(d.scalars.get("ha_peer_state")),
    ),
)


def _license_sensors() -> list[SophosSensorDescription]:
    out: list[SophosSensorDescription] = []
    for key, (_, name, enabled) in LICENSES.items():
        out.append(
            SophosSensorDescription(
                key=f"license_{key}",
                name=f"Lizenz {name}",
                icon="mdi:certificate",
                device_class=SensorDeviceClass.ENUM,
                options=list(LICENSE_STATES.values()),
                entity_category=EntityCategory.DIAGNOSTIC,
                entity_registry_enabled_default=enabled,
                value_fn=lambda d, k=key: LICENSE_STATES.get(d.licenses.get(k, (None, None))[0]),
            )
        )
        out.append(
            SophosSensorDescription(
                key=f"license_{key}_expiry",
                name=f"Lizenz {name} Ablauf",
                icon="mdi:calendar-clock",
                device_class=SensorDeviceClass.DATE,
                entity_category=EntityCategory.DIAGNOSTIC,
                entity_registry_enabled_default=enabled,
                value_fn=lambda d, k=key: _to_date(d.licenses.get(k, (None, None))[1]),
                attr_fn=lambda d, k=key: {"rohwert": d.licenses.get(k, (None, None))[1]},
            )
        )
    return out


def _to_date(raw: str | None) -> date | None:
    parsed: datetime | None = parse_license_date(raw)
    return parsed.date() if parsed else None


def _interface_sensors(name: str) -> list[SophosSensorDescription]:
    def _get(d: SnmpData):
        return d.interfaces.get(name)

    return [
        SophosSensorDescription(
            key=f"if_{name}_rx",
            name=f"{name} Download",
            icon="mdi:download-network",
            device_class=SensorDeviceClass.DATA_RATE,
            native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
            suggested_display_precision=2,
            state_class=SensorStateClass.MEASUREMENT,
            value_fn=lambda d: (i.rx_mbit if (i := _get(d)) else None),
            attr_fn=lambda d: (
                {"alias": i.alias, "linkgeschwindigkeit_mbit": i.speed_mbit}
                if (i := _get(d))
                else None
            ),
        ),
        SophosSensorDescription(
            key=f"if_{name}_tx",
            name=f"{name} Upload",
            icon="mdi:upload-network",
            device_class=SensorDeviceClass.DATA_RATE,
            native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
            suggested_display_precision=2,
            state_class=SensorStateClass.MEASUREMENT,
            value_fn=lambda d: (i.tx_mbit if (i := _get(d)) else None),
        ),
        SophosSensorDescription(
            key=f"if_{name}_rxtotal",
            name=f"{name} Empfangen gesamt",
            icon="mdi:download",
            device_class=SensorDeviceClass.DATA_SIZE,
            native_unit_of_measurement=UnitOfInformation.BYTES,
            suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
            suggested_display_precision=2,
            state_class=SensorStateClass.TOTAL_INCREASING,
            entity_registry_enabled_default=False,
            value_fn=lambda d: (i.rx_bytes if (i := _get(d)) else None),
        ),
        SophosSensorDescription(
            key=f"if_{name}_txtotal",
            name=f"{name} Gesendet gesamt",
            icon="mdi:upload",
            device_class=SensorDeviceClass.DATA_SIZE,
            native_unit_of_measurement=UnitOfInformation.BYTES,
            suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
            suggested_display_precision=2,
            state_class=SensorStateClass.TOTAL_INCREASING,
            entity_registry_enabled_default=False,
            value_fn=lambda d: (i.tx_bytes if (i := _get(d)) else None),
        ),
    ]


def _tunnel_sensor(name: str) -> SophosSensorDescription:
    return SophosSensorDescription(
        key=f"ipsec_{name}_tunnels",
        name=f"IPsec {name} aktive Tunnel",
        icon="mdi:vpn",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=lambda d: (t.active_tunnels if (t := d.tunnels.get(name)) else None),
    )


def _ap_sensor(name: str) -> SophosSensorDescription:
    return SophosSensorDescription(
        key=f"ap_{name}_clients",
        name=f"AP {name} Clients",
        icon="mdi:access-point",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: (a.clients if (a := d.access_points.get(name)) else None),
        attr_fn=lambda d: ({"modell": a.model} if (a := d.access_points.get(name)) else None),
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Sensoren anlegen."""
    coordinator = entry.runtime_data.snmp
    data = coordinator.data

    descriptions: list[SophosSensorDescription] = list(SYSTEM_SENSORS)
    if data.scalars.get("ha_status") == 1:
        descriptions.extend(HA_SENSORS)
    descriptions.extend(_license_sensors())
    for if_name in entry.options.get(CONF_INTERFACES, []):
        descriptions.extend(_interface_sensors(if_name))
    descriptions.extend(_tunnel_sensor(n) for n in data.tunnels)
    descriptions.extend(_ap_sensor(n) for n in data.access_points)

    async_add_entities(SophosSensor(coordinator, entry, desc) for desc in descriptions)


class SophosSensor(SophosEntity[SophosSnmpCoordinator], SensorEntity):
    """Ein SNMP-basierter Sensor."""

    entity_description: SophosSensorDescription

    def __init__(
        self,
        coordinator: SophosSnmpCoordinator,
        entry: SophosConfigEntry,
        description: SophosSensorDescription,
    ) -> None:
        super().__init__(coordinator, entry, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attr_fn is None:
            return None
        return self.entity_description.attr_fn(self.coordinator.data)
