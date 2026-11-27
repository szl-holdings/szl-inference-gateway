"""Pinned outbound origin for the loopback inference backend.

The only origin this process may dial is the one the deploy recipe names:
``recipe/entrypoint.sh`` sets ``ORIGIN_BACKEND_PORT`` and starts llama-server
with ``--host``. The scheme stays ``http`` when that recipe does not configure
TLS. A missing recipe, any other host, or a process port that disagrees with
the recipe fails closed. User-controlled request targets and redirects are
never concatenated onto this origin.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlunparse, urlsplit

_PORT_LINE = re.compile(r"(?m)^ORIGIN_BACKEND_PORT=([0-9]+)\s*$")
_HOST_FLAG = re.compile(r"--host\s+(\S+)")
_TLS_HINT = re.compile(r"--ssl\b|HTTPSConnection|https://127\.0\.0\.1")
_PORT_TEXT = re.compile(r"[1-9][0-9]{0,4}")
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})
_ALLOWED_PATHS = frozenset({"/health", "/v1/models", "/v1/chat/completions"})
_BLOCKED = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


class OriginConfigError(Exception):
    """The deploy recipe or process port does not name one pinned origin."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class OriginRejected(Exception):
    """A request target is not one of the vetted path literals."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PinnedOrigin:
    scheme: str
    host: str
    port: int

    @property
    def origin(self) -> str:
        return urlunparse((self.scheme, f"{self.host}:{self.port}", "", "", "", ""))


def default_entrypoint_path() -> Path:
    return Path(__file__).resolve().parents[2] / "recipe" / "entrypoint.sh"


def load_pinned_origin(
    backend_port: int | None = None,
    *,
    env_port: str | None = None,
    entrypoint: Path | None = None,
) -> PinnedOrigin:
    """Return the recipe origin when the process port matches it."""
    path = Path(entrypoint) if entrypoint is not None else default_entrypoint_path()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OriginConfigError("ORIGIN_DEPLOY_RECIPE_UNAVAILABLE") from exc
    pin = _parse_recipe(text)
    chosen = _explicit_port(backend_port, env_port)
    if chosen != pin.port:
        raise OriginConfigError("ORIGIN_BACKEND_PORT_NOT_ALLOWED")
    return pin


def vetted_literal_path(method: str, raw_target: str) -> str | None:
    """Map an exact request target to a path literal.

    The returned value is a constant. It is never the caller's string object
    reused as a URL.
    """
    if type(method) is not str or type(raw_target) is not str:
        return None
    if method == "GET" and raw_target == "/health":
        return "/health"
    if method == "GET" and raw_target == "/v1/models":
        return "/v1/models"
    if method == "POST" and raw_target == "/v1/chat/completions":
        return "/v1/chat/completions"
    return None


def build_pinned_url(pin: PinnedOrigin, method: str, raw_target: str) -> str:
    """Build the outbound URL from the pinned origin and a vetted path literal."""
    literal = vetted_literal_path(method, raw_target)
    if literal is None:
        raise OriginRejected("PATH_REJECTED")
    if pin.scheme != "http" or pin.host != "127.0.0.1" or type(pin.port) is not int:
        raise OriginRejected("ORIGIN_NOT_ALLOWLISTED")
    if not 1 <= pin.port <= 65535:
        raise OriginRejected("PORT_REJECTED")
    if literal == "/health":
        path = "/health"
    elif literal == "/v1/models":
        path = "/v1/models"
    elif literal == "/v1/chat/completions":
        path = "/v1/chat/completions"
    else:
        raise OriginRejected("PATH_REJECTED")
    return urlunparse((pin.scheme, f"{pin.host}:{pin.port}", path, "", "", ""))


def rejection_for_request_target(
    method: str,
    raw_target: str,
    *,
    pin: PinnedOrigin,
    resolve=None,
) -> str | None:
    """Return why a request target must not be dialed, or None when it is exact."""
    if vetted_literal_path(method, raw_target) is not None:
        return None
    reason = _explain(raw_target, pin, resolve, redirect=False)
    if reason is None:
        return "TARGET_REJECTED"
    return reason


def assess_redirect(location: str, *, pin: PinnedOrigin, resolve=None) -> str:
    """Return why a redirect location must not be requested."""
    reason = _explain(location, pin, resolve, redirect=True)
    if reason is None:
        return "REDIRECT_NOT_FOLLOWED"
    return reason


def _parse_recipe(text: str) -> PinnedOrigin:
    if _TLS_HINT.search(text):
        raise OriginConfigError("ORIGIN_SCHEME_UNPINNED")
    ports = _PORT_LINE.findall(text)
    if not ports:
        raise OriginConfigError("ORIGIN_BACKEND_UNCONFIGURED")
    if len(ports) != 1 or not _PORT_TEXT.fullmatch(ports[0]):
        raise OriginConfigError(
            "ORIGIN_BACKEND_PORT_INVALID" if len(ports) == 1 else "ORIGIN_BACKEND_PORT_NOT_ALLOWED"
        )
    port = int(ports[0])
    if port > 65535:
        raise OriginConfigError("ORIGIN_BACKEND_PORT_INVALID")
    hosts = _HOST_FLAG.findall(text)
    if not hosts or any(host != "127.0.0.1" for host in hosts):
        raise OriginConfigError("ORIGIN_BACKEND_HOST_NOT_ALLOWED")
    return PinnedOrigin(scheme="http", host="127.0.0.1", port=port)


def _explicit_port(backend_port: int | None, env_port: str | None) -> int:
    values: list[int] = []
    if backend_port is not None:
        if type(backend_port) is not int or not 1 <= backend_port <= 65535:
            raise OriginConfigError("ORIGIN_BACKEND_PORT_INVALID")
        values.append(backend_port)
    if env_port is not None and env_port != "":
        if type(env_port) is not str or not _PORT_TEXT.fullmatch(env_port):
            raise OriginConfigError("ORIGIN_BACKEND_PORT_INVALID")
        parsed = int(env_port)
        if parsed > 65535:
            raise OriginConfigError("ORIGIN_BACKEND_PORT_INVALID")
        values.append(parsed)
    if not values:
        raise OriginConfigError("ORIGIN_BACKEND_UNCONFIGURED")
    if any(value != values[0] for value in values):
        raise OriginConfigError("ORIGIN_BACKEND_PORT_NOT_ALLOWED")
    return values[0]


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return any(addr in network for network in _BLOCKED)


def _bad_path(path: str) -> bool:
    if path == "" or not path.startswith("/") or "//" in path:
        return True
    lowered = path.lower()
    return ".." in path or "%" in lowered or "\\" in path


def _assess_name(host: str, resolve) -> str:
    if resolve is None:
        return "HOST_NOT_ALLOWLISTED"
    try:
        first = [_canonical_ip(item) for item in list(resolve(host))]
        second = [_canonical_ip(item) for item in list(resolve(host))]
    except (OSError, TypeError, ValueError):
        return "HOST_NOT_ALLOWLISTED"
    if not first or not second:
        return "HOST_NOT_ALLOWLISTED"
    if set(first) != set(second):
        return "DNS_REBIND"
    if any(_blocked(ipaddress.ip_address(item)) for item in first):
        return "BLOCKED_ADDRESS"
    return "HOST_NOT_ALLOWLISTED"


def _canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(str(value).split("%", 1)[0]))


def _explain(raw: str, pin: PinnedOrigin, resolve, *, redirect: bool) -> str | None:
    if type(raw) is not str or raw == "" or any(char in raw for char in "\r\n\x00\t "):
        return "TARGET_REJECTED"
    if "\\" in raw:
        return "PATH_REJECTED"
    if raw.startswith("//"):
        return "SCHEME_REJECTED"
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        parsed_port = parts.port
    except ValueError:
        return "TARGET_REJECTED"
    if parts.username is not None or parts.password is not None:
        return "USERINFO_REJECTED"
    if "://" not in raw:
        return "PATH_REJECTED"
    if parts.scheme.lower() != "http":
        return "SCHEME_REJECTED"
    if not host:
        return "HOST_NOT_ALLOWLISTED"
    port = 80 if parsed_port is None else parsed_port
    path = parts.path or ""
    if host == pin.host:
        if port != pin.port:
            return "PORT_REJECTED"
        if parts.query or parts.fragment or _bad_path(path) or path not in _ALLOWED_PATHS:
            return "PATH_REJECTED"
        if redirect:
            return "BLOCKED_ADDRESS"
        return None
    address = _parse_ip(host)
    if address is not None and _blocked(address):
        return "BLOCKED_ADDRESS"
    if host.rstrip(".").lower() in _LOOPBACK_NAMES:
        return "BLOCKED_ADDRESS"
    if address is not None:
        return "HOST_NOT_ALLOWLISTED"
    return _assess_name(host, resolve)
