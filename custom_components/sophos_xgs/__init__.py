"""Sophos XGS Firewall – Home-Assistant-Integration."""

from __future__ import annotations

from dataclasses import dataclass
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import SophosApiClient
from .const import (
    CONF_API_PORT,
    CONF_INTERFACES,
    CONF_RULES,
    CONF_VERIFY_SSL,
    DEFAULT_API_PORT,
)
from .coordinator import SophosApiCoordinator, SophosSnmpCoordinator
from .snmp import SophosSnmpClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.SWITCH]


@dataclass
class SophosRuntimeData:
    """Laufzeitdaten eines Config-Eintrags."""

    snmp: SophosSnmpCoordinator
    api: SophosApiCoordinator
    device_id: str


type SophosConfigEntry = ConfigEntry[SophosRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Eintrag einrichten."""
    snmp_client = await SophosSnmpClient.async_create(hass, entry.data)
    api_client = SophosApiClient(
        async_get_clientsession(hass, verify_ssl=entry.data.get(CONF_VERIFY_SSL, False)),
        entry.data[CONF_HOST],
        entry.data.get(CONF_API_PORT, DEFAULT_API_PORT),
        entry.data[CONF_USERNAME],
        entry.data[CONF_PASSWORD],
    )

    snmp = SophosSnmpCoordinator(hass, entry, snmp_client)
    api = SophosApiCoordinator(hass, entry, api_client)
    try:
        await snmp.async_config_entry_first_refresh()
        await api.async_config_entry_first_refresh()
    except Exception:
        snmp_client.close()
        raise

    entry.runtime_data = SophosRuntimeData(
        snmp=snmp, api=api, device_id=entry.unique_id or entry.entry_id
    )
    entry.async_on_unload(snmp_client.close)

    _cleanup_deselected_entities(hass, entry)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Eintrag entladen."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _async_update_listener(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


def _cleanup_deselected_entities(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Entitäten für abgewählte Interfaces/Regeln aus der Registry entfernen."""
    registry = er.async_get(hass)
    base = entry.runtime_data.device_id
    interfaces = set(entry.options.get(CONF_INTERFACES, []))
    rules = set(entry.options.get(CONF_RULES, []))

    for ent in er.async_entries_for_config_entry(registry, entry.entry_id):
        uid = ent.unique_id
        if uid.startswith(f"{base}_rule_"):
            if uid.removeprefix(f"{base}_rule_") not in rules:
                registry.async_remove(ent.entity_id)
        elif uid.startswith(f"{base}_if_"):
            name = uid.removeprefix(f"{base}_if_").rsplit("_", 1)[0]
            if name not in interfaces:
                registry.async_remove(ent.entity_id)
