"""Einrichtungs- und Options-Dialog."""

from __future__ import annotations

from collections.abc import Mapping
import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import (
    FirewallRule,
    SophosApiAccessDenied,
    SophosApiAuthError,
    SophosApiClient,
    SophosApiError,
)
from .const import (
    AUTH_PROTOCOLS,
    CONF_API_INTERVAL,
    CONF_API_PORT,
    CONF_COMMUNITY,
    CONF_INTERFACES,
    CONF_RULES,
    CONF_SNMP_INTERVAL,
    CONF_SNMP_PORT,
    CONF_SNMP_VERSION,
    CONF_V3_AUTH_KEY,
    CONF_V3_AUTH_PROTO,
    CONF_V3_PRIV_KEY,
    CONF_V3_PRIV_PROTO,
    CONF_V3_USER,
    CONF_VERIFY_SSL,
    DEFAULT_API_INTERVAL,
    DEFAULT_API_PORT,
    DEFAULT_SNMP_INTERVAL,
    DEFAULT_SNMP_PORT,
    DOMAIN,
    OID_IF_NAME,
    PRIV_PROTOCOLS,
    SCALAR_OIDS,
    SNMP_V2C,
    SNMP_V3,
)
from .snmp import SnmpError, SophosSnmpClient

_LOGGER = logging.getLogger(__name__)

_PASSWORD = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
_PHYSICAL_PORT = re.compile(r"^Port\w+$")


class CannotConnectSnmp(Exception):
    """SNMP nicht erreichbar."""


async def _probe_snmp(hass: HomeAssistant, data: Mapping[str, Any]) -> dict[str, Any]:
    client = await SophosSnmpClient.async_create(hass, data)
    try:
        info = await client.async_get(
            {k: SCALAR_OIDS[k] for k in ("device_name", "device_type", "app_key", "fw_version")}
        )
        if info.get("device_name") is None and info.get("fw_version") is None:
            raise CannotConnectSnmp
        names = await client.async_walk(OID_IF_NAME)
    except SnmpError as err:
        raise CannotConnectSnmp from err
    finally:
        client.close()
    info["interfaces"] = sorted(
        {n for n in names.values() if isinstance(n, str) and n}, key=_natural_key
    )
    return info


async def _probe_api(hass: HomeAssistant, data: Mapping[str, Any]) -> dict[str, FirewallRule]:
    client = SophosApiClient(
        async_get_clientsession(hass, verify_ssl=data.get(CONF_VERIFY_SSL, False)),
        data[CONF_HOST],
        data.get(CONF_API_PORT, DEFAULT_API_PORT),
        data[CONF_USERNAME],
        data[CONF_PASSWORD],
    )
    return await client.async_get_firewall_rules()


def _natural_key(text: str) -> list[Any]:
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r"(\d+)", text)]


def _rule_options(rules: Mapping[str, FirewallRule]) -> list[SelectOptionDict]:
    return [
        SelectOptionDict(
            value=name,
            label=f"{name}{'' if rule.enabled else ' (deaktiviert)'}"
            + (f" – {rule.action}" if rule.action else ""),
        )
        for name, rule in rules.items()
    ]


def _entities_schema(
    interfaces: list[str],
    rules: Mapping[str, FirewallRule],
    sel_interfaces: list[str],
    sel_rules: list[str],
) -> dict[Any, Any]:
    if_options = sorted(set(interfaces) | set(sel_interfaces), key=_natural_key)
    rule_options = _rule_options(rules) + [
        SelectOptionDict(value=r, label=f"{r} (nicht mehr vorhanden)")
        for r in sel_rules
        if r not in rules
    ]
    return {
        vol.Optional(CONF_INTERFACES, default=sel_interfaces): SelectSelector(
            SelectSelectorConfig(
                options=if_options, multiple=True, mode=SelectSelectorMode.DROPDOWN
            )
        ),
        vol.Optional(CONF_RULES, default=sel_rules): SelectSelector(
            SelectSelectorConfig(
                options=rule_options, multiple=True, mode=SelectSelectorMode.DROPDOWN
            )
        ),
    }


class SophosXgsConfigFlow(ConfigFlow, domain=DOMAIN):
    """Einrichtung der Sophos XGS."""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._snmp_info: dict[str, Any] = {}
        self._rules: dict[str, FirewallRule] = {}

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return SophosXgsOptionsFlow()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Schritt 1: Verbindung und API-Zugang."""
        if user_input is not None:
            self._data = dict(user_input)
            if user_input[CONF_SNMP_VERSION] == SNMP_V3:
                return await self.async_step_snmp_v3()
            return await self.async_step_snmp_v2c()

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): _PASSWORD,
                vol.Required(CONF_API_PORT, default=DEFAULT_API_PORT): int,
                vol.Required(CONF_VERIFY_SSL, default=False): bool,
                vol.Required(CONF_SNMP_VERSION, default=SNMP_V2C): SelectSelector(
                    SelectSelectorConfig(
                        options=[SNMP_V2C, SNMP_V3], mode=SelectSelectorMode.LIST
                    )
                ),
                vol.Required(CONF_SNMP_PORT, default=DEFAULT_SNMP_PORT): int,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_snmp_v2c(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Schritt 2a: SNMP v2c."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._data.update(user_input)
            errors = await self._async_validate()
            if not errors:
                return await self.async_step_entities()
        return self.async_show_form(
            step_id="snmp_v2c",
            data_schema=vol.Schema({vol.Required(CONF_COMMUNITY): _PASSWORD}),
            errors=errors,
        )

    async def async_step_snmp_v3(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Schritt 2b: SNMP v3."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._data.update(user_input)
            errors = await self._async_validate()
            if not errors:
                return await self.async_step_entities()
        schema = vol.Schema(
            {
                vol.Required(CONF_V3_USER): str,
                vol.Required(CONF_V3_AUTH_PROTO, default="SHA"): vol.In(AUTH_PROTOCOLS),
                vol.Optional(CONF_V3_AUTH_KEY, default=""): _PASSWORD,
                vol.Required(CONF_V3_PRIV_PROTO, default="AES"): vol.In(PRIV_PROTOCOLS),
                vol.Optional(CONF_V3_PRIV_KEY, default=""): _PASSWORD,
            }
        )
        return self.async_show_form(step_id="snmp_v3", data_schema=schema, errors=errors)

    async def _async_validate(self) -> dict[str, str]:
        try:
            self._snmp_info = await _probe_snmp(self.hass, self._data)
        except CannotConnectSnmp:
            return {"base": "cannot_connect_snmp"}
        except Exception:
            _LOGGER.exception("Unerwarteter Fehler bei SNMP-Test")
            return {"base": "unknown"}

        try:
            self._rules = await _probe_api(self.hass, self._data)
        except SophosApiAuthError:
            return {"base": "invalid_auth"}
        except SophosApiAccessDenied:
            return {"base": "api_access_denied"}
        except SophosApiError:
            return {"base": "cannot_connect_api"}
        except Exception:
            _LOGGER.exception("Unerwarteter Fehler bei API-Test")
            return {"base": "unknown"}

        unique = self._snmp_info.get("app_key") or self._data[CONF_HOST]
        await self.async_set_unique_id(str(unique))
        self._abort_if_unique_id_configured(updates={CONF_HOST: self._data[CONF_HOST]})
        return {}

    async def async_step_entities(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Schritt 3: Interfaces und Regeln auswählen."""
        if user_input is not None:
            title = self._snmp_info.get("device_name") or self._data[CONF_HOST]
            return self.async_create_entry(
                title=title,
                data=self._data,
                options={
                    CONF_INTERFACES: user_input.get(CONF_INTERFACES, []),
                    CONF_RULES: user_input.get(CONF_RULES, []),
                    CONF_SNMP_INTERVAL: DEFAULT_SNMP_INTERVAL,
                    CONF_API_INTERVAL: DEFAULT_API_INTERVAL,
                },
            )

        interfaces: list[str] = self._snmp_info.get("interfaces", [])
        default_ifs = [i for i in interfaces if _PHYSICAL_PORT.match(i)]
        return self.async_show_form(
            step_id="entities",
            data_schema=vol.Schema(
                _entities_schema(interfaces, self._rules, default_ifs, [])
            ),
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Neue Zugangsdaten anfordern."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {**entry.data, **user_input}
            try:
                await _probe_api(self.hass, data)
            except SophosApiAuthError:
                errors["base"] = "invalid_auth"
            except SophosApiAccessDenied:
                errors["base"] = "api_access_denied"
            except SophosApiError:
                errors["base"] = "cannot_connect_api"
            else:
                return self.async_update_reload_and_abort(entry, data_updates=user_input)
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=entry.data[CONF_USERNAME]): str,
                    vol.Required(CONF_PASSWORD): _PASSWORD,
                }
            ),
            errors=errors,
        )


class SophosXgsOptionsFlow(OptionsFlow):
    """Optionen: Interfaces, Regeln, Abfrageintervalle."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self.config_entry
        if user_input is not None:
            return self.async_create_entry(
                data={
                    CONF_INTERFACES: user_input.get(CONF_INTERFACES, []),
                    CONF_RULES: user_input.get(CONF_RULES, []),
                    CONF_SNMP_INTERVAL: int(user_input[CONF_SNMP_INTERVAL]),
                    CONF_API_INTERVAL: int(user_input[CONF_API_INTERVAL]),
                }
            )

        runtime = getattr(entry, "runtime_data", None)
        if runtime is None or runtime.snmp.data is None:
            return self.async_abort(reason="not_loaded")

        interfaces = list(runtime.snmp.data.interfaces)
        rules = runtime.api.data or {}
        schema = _entities_schema(
            interfaces,
            rules,
            entry.options.get(CONF_INTERFACES, []),
            entry.options.get(CONF_RULES, []),
        )
        schema.update(
            {
                vol.Required(
                    CONF_SNMP_INTERVAL,
                    default=entry.options.get(CONF_SNMP_INTERVAL, DEFAULT_SNMP_INTERVAL),
                ): NumberSelector(
                    NumberSelectorConfig(
                        min=10, max=600, step=5, unit_of_measurement="s",
                        mode=NumberSelectorMode.BOX,
                    )
                ),
                vol.Required(
                    CONF_API_INTERVAL,
                    default=entry.options.get(CONF_API_INTERVAL, DEFAULT_API_INTERVAL),
                ): NumberSelector(
                    NumberSelectorConfig(
                        min=15, max=3600, step=5, unit_of_measurement="s",
                        mode=NumberSelectorMode.BOX,
                    )
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=vol.Schema(schema))
