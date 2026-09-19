"""Egress control: where the gateway is allowed to send a request.

A gateway that will POST to whatever URL it is handed is an SSRF primitive with
authentication in front of it, and ``169.254.169.254`` is the first thing anyone
tries. The client-controlled half of that was always closed — destinations are
selected by *name* from a map built at startup, so a caller cannot choose a URL.
This module closes the operator-controlled half.

## What it checks, in order

1. **Scheme.** ``https`` always; ``http`` only where explicitly allowed, because
   a local model on loopback is a legitimate deployment and forcing TLS on it
   would push operators to disable verification instead.
2. **Host allowlist**, when one is configured. Exact, case-insensitive.
3. **Address.** Every address the host resolves to must be globally routable.
   Loopback, link-local, private, reserved, and multicast ranges are refused
   unless the destination is explicitly marked as local.

## The residual, stated plainly

``httpx`` performs its own DNS resolution when it connects, so between our check
and its connection the name could resolve differently — classic TOCTOU, and the
mechanism behind DNS rebinding. Closing it completely means pinning the
connection to the address we validated, which is a custom transport.

We validate **per request** rather than only at startup, which closes
misconfiguration and slow rebinding. Fast rebinding remains open, is recorded
here rather than in a footnote, and is on the list for the independent review.
For the v1 threat model — where the base URL is operator configuration, not
attacker input — that is a proportionate stopping point.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

logger = logging.getLogger("gateway.routing.egress")


class EgressBlockedError(Exception):
    """A destination is not permitted. Fatal at startup, and per request.

    The message names the host and the reason -- both operator configuration,
    never customer content.
    """


def _is_globally_routable(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve(host: str) -> list[str]:
    """Every address ``host`` resolves to, or the literal address itself."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return [host]

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EgressBlockedError(
            f"destination host {host!r} does not resolve: {exc.strerror or exc}"
        ) from exc
    return sorted({info[4][0] for info in infos})


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """Where one destination is allowed to point.

    Per destination rather than global, because ``local`` and ``external`` have
    genuinely different requirements: routing to a model on loopback is the
    entire point of the ``route_local`` policy action, while an external
    provider resolving to a private address is either a mistake or an attack.
    """

    name: str = "external"
    #: Permit loopback, private, and link-local addresses. True for `local`.
    allow_private: bool = False
    #: Permit plaintext HTTP. Follows `allow_private` unless set explicitly.
    allow_http: bool | None = None
    #: When non-empty, the host must appear here. Exact, case-insensitive.
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)

    @property
    def http_permitted(self) -> bool:
        return self.allow_private if self.allow_http is None else self.allow_http

    def validate(self, url: str) -> None:
        """Raise :class:`EgressBlockedError` unless ``url`` is permitted."""
        parts = urlsplit(url)

        if parts.scheme not in ("http", "https"):
            raise EgressBlockedError(
                f"destination {self.name!r}: scheme {parts.scheme or '(none)'!r} is not "
                "permitted; use https, or http for an explicitly local destination"
            )
        if parts.scheme == "http" and not self.http_permitted:
            raise EgressBlockedError(
                f"destination {self.name!r}: plaintext http is not permitted for a "
                "non-local destination. Prompts would cross the network in clear."
            )

        host = parts.hostname
        if not host:
            raise EgressBlockedError(f"destination {self.name!r}: URL has no host")

        if self.allowed_hosts and host.lower() not in self.allowed_hosts:
            raise EgressBlockedError(
                f"destination {self.name!r}: host {host!r} is not in the egress "
                f"allowlist ({sorted(self.allowed_hosts)})"
            )

        addresses = _resolve(host)
        if not addresses:
            raise EgressBlockedError(f"destination {self.name!r}: {host!r} resolved to nothing")

        for address in addresses:
            if not _is_globally_routable(address) and not self.allow_private:
                raise EgressBlockedError(
                    f"destination {self.name!r}: {host!r} resolves to {address}, which is "
                    "loopback, link-local, private, or reserved. Refusing -- this is how "
                    "a gateway becomes a proxy to the metadata service."
                )

    def describe(self) -> dict[str, object]:
        """Operator-facing summary. Configuration only, no request data."""
        return {
            "destination": self.name,
            "allow_private": self.allow_private,
            "allow_http": self.http_permitted,
            "allowed_hosts": sorted(self.allowed_hosts),
        }


def policy_for(
    destination: str,
    *,
    allowed_hosts: frozenset[str] = frozenset(),
    allow_private_override: bool | None = None,
) -> EgressPolicy:
    """The default policy for a named destination.

    ``local`` allows private addresses because that is what it is for; every
    other destination does not. An operator can override globally, and the
    override is logged loudly because it removes the SSRF control.
    """
    allow_private = destination == "local"
    if allow_private_override is not None:
        if allow_private_override and not allow_private:
            logger.warning(
                "SAG_EGRESS_ALLOW_PRIVATE is set: destination %r may now resolve to "
                "private or link-local addresses. This disables the SSRF control.",
                destination,
            )
        allow_private = allow_private_override
    return EgressPolicy(name=destination, allow_private=allow_private, allowed_hosts=allowed_hosts)
