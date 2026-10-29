"""Schlanker asynchroner SNMP-Client (pysnmp >= 7) für SFOS."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

from pyasn1.type import univ
from pysnmp.entity import config as snmp_cfg
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
)

from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant

from .const import (
    CONF_COMMUNITY,
    CONF_SNMP_PORT,
    CONF_SNMP_VERSION,
    CONF_V3_AUTH_KEY,
    CONF_V3_AUTH_PROTO,
    CONF_V3_PRIV_KEY,
    CONF_V3_PRIV_PROTO,
    CONF_V3_USER,
    DEFAULT_SNMP_PORT,
    SNMP_V3,
)

_LOGGER = logging.getLogger(__name__)

_AUTH_MAP = {
    "none": snmp_cfg.usmNoAuthProtocol,
    "MD5": snmp_cfg.usmHMACMD5AuthProtocol,
    "SHA": snmp_cfg.usmHMACSHAAuthProtocol,
    "SHA256": snmp_cfg.usmHMAC192SHA256AuthProtocol,
    "SHA512": snmp_cfg.usmHMAC384SHA512AuthProtocol,
}
_PRIV_MAP = {
    "none": snmp_cfg.usmNoPrivProtocol,
    "DES": snmp_cfg.usmDESPrivProtocol,
    "AES": snmp_cfg.usmAesCfb128Protocol,
    "AES256": snmp_cfg.usmAesCfb256Protocol,
}

_MISSING = {"NoSuchObject", "NoSuchInstance", "EndOfMibView"}
_GET_CHUNK = 20


class SnmpError(Exception):
    """SNMP-Abfrage fehlgeschlagen."""


def _convert(value: Any) -> Any:
    """pyasn1-Wert in einen Python-Wert umwandeln."""
    name = value.__class__.__name__
    if name in _MISSING:
        return None
    if name == "IpAddress":
        return value.prettyPrint()
    if isinstance(value, univ.OctetString):
        raw = bytes(value)
        return raw.decode("utf-8", errors="replace").strip("\x00").strip()
    if isinstance(value, univ.Integer):
        return int(value)
    return value.prettyPrint()


def _build_auth(conf: Mapping[str, Any]) -> CommunityData | UsmUserData:
    if conf.get(CONF_SNMP_VERSION) == SNMP_V3:
        auth_proto = conf.get(CONF_V3_AUTH_PROTO, "SHA")
        priv_proto = conf.get(CONF_V3_PRIV_PROTO, "AES")
        auth_key = conf.get(CONF_V3_AUTH_KEY) or None
        priv_key = conf.get(CONF_V3_PRIV_KEY) or None
        if auth_proto == "none" or not auth_key:
            auth_proto, auth_key = "none", None
        if priv_proto == "none" or not priv_key or auth_key is None:
            priv_proto, priv_key = "none", None
        return UsmUserData(
            conf[CONF_V3_USER],
            authKey=auth_key,
            privKey=priv_key,
            authProtocol=_AUTH_MAP[auth_proto],
            privProtocol=_PRIV_MAP[priv_proto],
        )
    return CommunityData(conf[CONF_COMMUNITY], mpModel=1)


class SophosSnmpClient:
    """Liest Werte per SNMP von der Firewall."""

    def __init__(self, engine: SnmpEngine, host: str, port: int, auth: Any) -> None:
        self._engine = engine
        self._host = host
        self._port = port
        self._auth = auth
        self._transport: UdpTransportTarget | None = None

    @classmethod
    async def async_create(
        cls, hass: HomeAssistant, conf: Mapping[str, Any]
    ) -> SophosSnmpClient:
        # Das Anlegen der Engine lädt MIB-Module von der Platte -> Executor
        engine = await hass.async_add_executor_job(SnmpEngine)
        return cls(
            engine,
            conf[CONF_HOST],
            int(conf.get(CONF_SNMP_PORT, DEFAULT_SNMP_PORT)),
            _build_auth(conf),
        )

    async def _target(self) -> UdpTransportTarget:
        if self._transport is None:
            self._transport = await UdpTransportTarget.create(
                (self._host, self._port), timeout=3, retries=2
            )
        return self._transport

    async def async_get(self, oids: Mapping[str, str]) -> dict[str, Any]:
        """Mehrere Skalare abfragen. Rückgabe: key -> Wert (None, falls nicht vorhanden)."""
        target = await self._target()
        by_oid = {oid: key for key, oid in oids.items()}
        result: dict[str, Any] = dict.fromkeys(oids)
        items = list(by_oid)
        for start in range(0, len(items), _GET_CHUNK):
            chunk = items[start : start + _GET_CHUNK]
            err_ind, err_stat, err_idx, var_binds = await get_cmd(
                self._engine,
                self._auth,
                target,
                ContextData(),
                *(ObjectType(ObjectIdentity(oid)) for oid in chunk),
                lookupMib=False,
            )
            if err_ind:
                raise SnmpError(str(err_ind))
            if err_stat:
                # Bei SNMPv1 o. ä. bricht ein einzelnes fehlendes OID die ganze PDU
                raise SnmpError(f"{err_stat.prettyPrint()} (Index {err_idx})")
            for name, value in var_binds:
                oid = str(name).lstrip(".")
                if oid in by_oid:
                    result[by_oid[oid]] = _convert(value)
        return result

    async def async_walk(self, base_oid: str) -> dict[str, Any]:
        """Teilbaum abfragen. Rückgabe: Index-Suffix -> Wert."""
        target = await self._target()
        prefix = base_oid.lstrip(".") + "."
        out: dict[str, Any] = {}
        async for err_ind, err_stat, err_idx, var_binds in bulk_walk_cmd(
            self._engine,
            self._auth,
            target,
            ContextData(),
            0,
            25,
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
            lookupMib=False,
        ):
            if err_ind:
                raise SnmpError(str(err_ind))
            if err_stat:
                raise SnmpError(f"{err_stat.prettyPrint()} (Index {err_idx})")
            for name, value in var_binds:
                oid = str(name).lstrip(".")
                if not oid.startswith(prefix):
                    continue
                converted = _convert(value)
                if converted is not None:
                    out[oid[len(prefix) :]] = converted
        return out

    def close(self) -> None:
        """Dispatcher der Engine schließen."""
        for attr in ("close_dispatcher", "closeDispatcher"):
            func = getattr(self._engine, attr, None)
            if func:
                try:
                    func()
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("Fehler beim Schließen der SNMP-Engine", exc_info=True)
                return
        dispatcher = getattr(self._engine, "transport_dispatcher", None) or getattr(
            self._engine, "transportDispatcher", None
        )
        if dispatcher is not None:
            for attr in ("close_dispatcher", "closeDispatcher"):
                func = getattr(dispatcher, attr, None)
                if func:
                    try:
                        func()
                    except Exception:  # noqa: BLE001
                        pass
                    return
