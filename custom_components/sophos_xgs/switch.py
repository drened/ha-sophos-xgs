"""Schalter: Firewall-Regeln aktivieren/deaktivieren."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.exceptions import HomeAssistantError

from .api import SophosApiError
from .const import CONF_RULES
from .coordinator import SophosApiCoordinator
from .entity import SophosEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

    from . import SophosConfigEntry

# Schreibzugriffe auf die Firewall nacheinander
PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Schalter für die ausgewählten Regeln anlegen."""
    api = entry.runtime_data.api
    async_add_entities(
        SophosRuleSwitch(api, entry, name)
        for name in entry.options.get(CONF_RULES, [])
    )


class SophosRuleSwitch(SophosEntity[SophosApiCoordinator], SwitchEntity):
    """Eine Firewall-Regel als Schalter."""

    _attr_icon = "mdi:wall-fire"

    def __init__(
        self, coordinator: SophosApiCoordinator, entry: SophosConfigEntry, rule: str
    ) -> None:
        super().__init__(coordinator, entry, f"rule_{rule}")
        self._rule = rule
        self._attr_name = f"Regel {rule}"

    @property
    def available(self) -> bool:
        return super().available and self._rule in (self.coordinator.data or {})

    @property
    def is_on(self) -> bool | None:
        rule = (self.coordinator.data or {}).get(self._rule)
        return rule.enabled if rule else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        rule = (self.coordinator.data or {}).get(self._rule)
        if rule is None:
            return None
        return {
            "beschreibung": rule.description,
            "aktion": rule.action,
            "typ": rule.policy_type,
            "ip_familie": rule.ip_family,
        }

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_set(False)

    async def _async_set(self, enabled: bool) -> None:
        try:
            await self.coordinator.client.async_set_firewall_rule(self._rule, enabled)
        except SophosApiError as err:
            raise HomeAssistantError(
                f"Regel '{self._rule}' konnte nicht {'aktiviert' if enabled else 'deaktiviert'} werden: {err}"
            ) from err

        # Sofort im UI anzeigen, danach mit der Firewall abgleichen
        data = dict(self.coordinator.data or {})
        if self._rule in data:
            data[self._rule] = replace(data[self._rule], enabled=enabled)
            self.coordinator.async_set_updated_data(data)
        await self.coordinator.async_request_refresh()
