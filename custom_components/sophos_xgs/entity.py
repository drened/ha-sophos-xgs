"""Gemeinsame Basisklassen."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.const import CONF_HOST
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import CONF_API_PORT, DEFAULT_API_PORT, DOMAIN, MANUFACTURER

if TYPE_CHECKING:
    from . import SophosConfigEntry


def build_device_info(entry: SophosConfigEntry) -> DeviceInfo:
    """Geräteinfo aus den aktuellen SNMP-Daten."""
    scalars = entry.runtime_data.snmp.data.scalars if entry.runtime_data.snmp.data else {}
    host = entry.data[CONF_HOST]
    port = entry.data.get(CONF_API_PORT, DEFAULT_API_PORT)
    return DeviceInfo(
        identifiers={(DOMAIN, entry.runtime_data.device_id)},
        name=scalars.get("device_name") or entry.title,
        manufacturer=MANUFACTURER,
        model=scalars.get("device_type") or "XGS",
        sw_version=scalars.get("fw_version"),
        serial_number=scalars.get("app_key"),
        configuration_url=f"https://{host}:{port}",
    )


class SophosEntity[_T: DataUpdateCoordinator[Any]](CoordinatorEntity[_T]):
    """Basis für alle Entitäten der Integration."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: _T, entry: SophosConfigEntry, key: str) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.runtime_data.device_id}_{key}"
        self._attr_device_info = build_device_info(entry)
