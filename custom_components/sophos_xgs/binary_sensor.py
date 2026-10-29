"""Binäre Sensoren der Sophos-XGS-Integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import callback

from .const import (
    CONF_INTERFACES,
    HA_STATES,
    LICENSE_PROBLEM_STATES,
    LICENSE_STATES,
    LICENSES,
    SERVICE_RUNNING,
    SERVICE_STATES,
    SERVICES,
)
from .coordinator import SnmpData, SophosApiCoordinator, SophosSnmpCoordinator
from .entity import SophosEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from . import SophosConfigEntry

PARALLEL_UPDATES = 0

_TUNNEL_STATES = {0: "inaktiv", 1: "aktiv", 2: "teilweise aktiv"}


@dataclass(frozen=True, kw_only=True)
class SophosBinaryDescription(BinarySensorEntityDescription):
    """Beschreibung eines binären SNMP-Sensors."""

    value_fn: Callable[[SnmpData], bool | None]
    attr_fn: Callable[[SnmpData], dict[str, Any] | None] | None = None
    exists_fn: Callable[[SnmpData], bool] | None = None


def _service(key: str, name: str, enabled: bool) -> SophosBinaryDescription:
    return SophosBinaryDescription(
        key=f"service_{key}",
        name=f"Dienst {name}",
        device_class=BinarySensorDeviceClass.RUNNING,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=enabled,
        value_fn=lambda d: (
            None if (s := d.services.get(key)) is None else s == SERVICE_RUNNING
        ),
        attr_fn=lambda d: {"status": SERVICE_STATES.get(d.services.get(key))},
    )


def _license_problem(d: SnmpData) -> bool:
    return any(
        LICENSE_STATES.get(status) in LICENSE_PROBLEM_STATES
        for status, _ in d.licenses.values()
    )


def _license_attrs(d: SnmpData) -> dict[str, Any]:
    return {
        LICENSES[key][1]: LICENSE_STATES.get(status)
        for key, (status, _) in d.licenses.items()
        if LICENSE_STATES.get(status) not in (None, "none")
    }


LICENSE_PROBLEM = SophosBinaryDescription(
    key="license_problem",
    name="Lizenzproblem",
    icon="mdi:certificate-outline",
    device_class=BinarySensorDeviceClass.PROBLEM,
    value_fn=_license_problem,
    attr_fn=_license_attrs,
)

HA_PROBLEM = SophosBinaryDescription(
    key="ha_problem",
    name="HA-Cluster-Problem",
    device_class=BinarySensorDeviceClass.PROBLEM,
    value_fn=lambda d: "faulty"
    in (
        HA_STATES.get(d.scalars.get("ha_state")),
        HA_STATES.get(d.scalars.get("ha_peer_state")),
    ),
)


def _interface(name: str) -> SophosBinaryDescription:
    return SophosBinaryDescription(
        key=f"if_{name}_link",
        name=f"{name} Link",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda d: (i.up if (i := d.interfaces.get(name)) else None),
        attr_fn=lambda d: (
            {"alias": i.alias, "linkgeschwindigkeit_mbit": i.speed_mbit}
            if (i := d.interfaces.get(name))
            else None
        ),
    )


def _tunnel(name: str) -> SophosBinaryDescription:
    return SophosBinaryDescription(
        key=f"ipsec_{name}",
        name=f"IPsec {name}",
        icon="mdi:vpn",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda d: (
            t.status in (1, 2) if (t := d.tunnels.get(name)) and t.status is not None else None
        ),
        attr_fn=lambda d: (
            {
                "status": _TUNNEL_STATES.get(t.status),
                "aktiviert": t.activated == 1,
                "aktive_tunnel": t.active_tunnels,
            }
            if (t := d.tunnels.get(name))
            else None
        ),
        exists_fn=lambda d: name in d.tunnels,
    )


def _access_point(name: str) -> SophosBinaryDescription:
    return SophosBinaryDescription(
        key=f"ap_{name}",
        name=f"AP {name}",
        icon="mdi:access-point-network",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda d: (a.connected if (a := d.access_points.get(name)) else None),
        exists_fn=lambda d: name in d.access_points,
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Binäre Sensoren anlegen."""
    snmp = entry.runtime_data.snmp
    data = snmp.data

    descriptions: list[SophosBinaryDescription] = [
        _service(key, name, enabled) for key, (_, name, enabled) in SERVICES.items()
    ]
    descriptions.append(LICENSE_PROBLEM)
    if data.scalars.get("ha_status") == 1:
        descriptions.append(HA_PROBLEM)
    descriptions.extend(_interface(n) for n in entry.options.get(CONF_INTERFACES, []))
    entities: list[BinarySensorEntity] = [
        SophosBinarySensor(snmp, entry, desc) for desc in descriptions
    ]
    entities.append(SophosReachableSensor(snmp, entry, "snmp_reachable", "Erreichbar (SNMP)"))
    entities.append(
        SophosReachableSensor(entry.runtime_data.api, entry, "api_reachable", "Erreichbar (API)")
    )
    async_add_entities(entities)

    # IPsec-Verbindungen und Access Points: auch später hinzugekommene anlegen
    known_tunnels: set[str] = set()
    known_aps: set[str] = set()

    @callback
    def _add_dynamic() -> None:
        current = snmp.data
        if current is None:
            return
        new: list[SophosBinarySensor] = []
        for name in current.tunnels.keys() - known_tunnels:
            known_tunnels.add(name)
            new.append(SophosBinarySensor(snmp, entry, _tunnel(name)))
        for name in current.access_points.keys() - known_aps:
            known_aps.add(name)
            new.append(SophosBinarySensor(snmp, entry, _access_point(name)))
        if new:
            async_add_entities(new)

    _add_dynamic()
    entry.async_on_unload(snmp.async_add_listener(_add_dynamic))


class SophosBinarySensor(SophosEntity[SophosSnmpCoordinator], BinarySensorEntity):
    """Ein SNMP-basierter binärer Sensor."""

    entity_description: SophosBinaryDescription

    def __init__(
        self,
        coordinator: SophosSnmpCoordinator,
        entry: SophosConfigEntry,
        description: SophosBinaryDescription,
    ) -> None:
        super().__init__(coordinator, entry, description.key)
        self.entity_description = description

    @property
    def available(self) -> bool:
        exists = self.entity_description.exists_fn
        return super().available and (exists is None or exists(self.coordinator.data))

    @property
    def is_on(self) -> bool | None:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attr_fn is None:
            return None
        return self.entity_description.attr_fn(self.coordinator.data)


class SophosReachableSensor(SophosEntity, BinarySensorEntity):
    """Zeigt an, ob die letzte Abfrage erfolgreich war (bleibt immer verfügbar)."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: SophosSnmpCoordinator | SophosApiCoordinator,
        entry: SophosConfigEntry,
        key: str,
        name: str,
    ) -> None:
        super().__init__(coordinator, entry, key)
        self._attr_name = name

    @property
    def available(self) -> bool:
        return True

    @property
    def is_on(self) -> bool:
        return self.coordinator.last_update_success
