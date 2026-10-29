"""Client für die SFOS XML-API (/webconsole/APIController)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

import aiohttp

_LOGGER = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=30)


class SophosApiError(Exception):
    """Allgemeiner API-Fehler."""


class SophosApiConnectionError(SophosApiError):
    """Firewall nicht erreichbar."""


class SophosApiAuthError(SophosApiError):
    """Benutzername/Passwort falsch."""


class SophosApiAccessDenied(SophosApiError):
    """API deaktiviert oder IP-Adresse von Home Assistant nicht freigegeben."""


@dataclass(slots=True)
class FirewallRule:
    """Vereinfachte Sicht auf eine Firewall-Regel."""

    name: str
    enabled: bool
    description: str | None = None
    policy_type: str | None = None
    action: str | None = None
    ip_family: str | None = None


class SophosApiClient:
    """Minimaler XML-API-Client."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
    ) -> None:
        self._session = session
        self._url = f"https://{host}:{port}/webconsole/APIController"
        self._username = username
        self._password = password
        # Schreibzugriffe nacheinander ausführen
        self._lock = asyncio.Lock()

    async def _request(self, inner: str) -> ET.Element:
        reqxml = (
            "<Request>"
            "<Login>"
            f"<Username>{escape(self._username)}</Username>"
            f"<Password>{escape(self._password)}</Password>"
            "</Login>"
            f"{inner}"
            "</Request>"
        )
        try:
            async with self._session.post(
                self._url, data={"reqxml": reqxml}, timeout=_TIMEOUT
            ) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    raise SophosApiConnectionError(f"HTTP {resp.status}")
        except (aiohttp.ClientError, TimeoutError) as err:
            raise SophosApiConnectionError(str(err)) from err

        try:
            root = ET.fromstring(text)
        except ET.ParseError as err:
            raise SophosApiError(f"Ungültige Antwort der Firewall: {text[:200]}") from err

        # Fehler auf Request-Ebene, z. B. 534 = IP nicht erlaubt
        status = root.find("Status")
        if status is not None and status.get("code") not in (None, "200", "216"):
            msg = (status.text or "").strip()
            if status.get("code") in ("534", "532", "529"):
                raise SophosApiAccessDenied(msg or f"Code {status.get('code')}")
            raise SophosApiError(msg or f"Code {status.get('code')}")

        login_status = (root.findtext("Login/status") or "").strip()
        if login_status and "success" not in login_status.lower():
            raise SophosApiAuthError(login_status)
        return root

    @staticmethod
    def _parse_rule(elem: ET.Element) -> FirewallRule:
        action = elem.findtext("NetworkPolicy/Action") or elem.findtext(
            "UserPolicy/Action"
        )
        return FirewallRule(
            name=(elem.findtext("Name") or "").strip(),
            enabled=(elem.findtext("Status") or "").strip().lower() == "enable",
            description=(elem.findtext("Description") or "").strip() or None,
            policy_type=(elem.findtext("PolicyType") or "").strip() or None,
            action=(action or "").strip() or None,
            ip_family=(elem.findtext("IPFamily") or "").strip() or None,
        )

    async def async_get_firewall_rules(self) -> dict[str, FirewallRule]:
        """Alle Firewall-Regeln lesen (Reihenfolge wie auf der Firewall)."""
        root = await self._request("<Get><FirewallRule></FirewallRule></Get>")
        rules: dict[str, FirewallRule] = {}
        for elem in root.findall("FirewallRule"):
            if elem.find("Name") is None:
                # z. B. <FirewallRule><Status>No. of records Zero.</Status></FirewallRule>
                continue
            rule = self._parse_rule(elem)
            if rule.name:
                rules[rule.name] = rule
        return rules

    async def async_set_firewall_rule(self, name: str, enabled: bool) -> None:
        """Regel aktivieren/deaktivieren.

        SFOS erwartet beim Update die vollständige Regel. Deshalb wird die Regel
        gelesen, nur <Status> geändert und komplett zurückgeschrieben.
        """
        async with self._lock:
            root = await self._request("<Get><FirewallRule></FirewallRule></Get>")
            target: ET.Element | None = None
            for elem in root.findall("FirewallRule"):
                if (elem.findtext("Name") or "").strip() == name:
                    target = elem
                    break
            if target is None:
                raise SophosApiError(f"Firewall-Regel '{name}' nicht gefunden")

            target.attrib.pop("transactionid", None)
            target.tail = None
            status = target.find("Status")
            if status is None:
                status = ET.SubElement(target, "Status")
            status.text = "Enable" if enabled else "Disable"

            payload = ET.tostring(target, encoding="unicode")
            resp = await self._request(f'<Set operation="update">{payload}</Set>')

            result = resp.find("FirewallRule/Status")
            if result is None:
                raise SophosApiError("Keine Bestätigung der Firewall erhalten")
            if result.get("code") != "200":
                raise SophosApiError(
                    (result.text or "").strip() or f"Code {result.get('code')}"
                )
