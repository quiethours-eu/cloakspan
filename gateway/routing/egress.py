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
   unless the destination is explicitly marked as local. While
   ``SAG_LOCAL_ROUTING`` is on, `local` is held to the inverse: every address
   must be loopback or on a private network, from an explicit list.

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


#: Where a destination may point when it must be on the operator's own network:
#: loopback, RFC 1918, RFC 6598 shared address space (which Tailscale uses),
#: IPv6 loopback, and IPv6 unique local addresses. Nothing else -- so not
#: link-local, which is where ``169.254.169.254`` lives.
#:
#: An explicit list rather than ``is_private`` or ``is_global``. CPython revised
#: those tables in 2024 (CVE-2024-4032), so their answer depends on the
#: interpreter; and ``_is_globally_routable`` above treats ``100.64.0.0/10`` as
#: routable, which would refuse a model reached over Tailscale. A list reads the
#: same on every interpreter and in every review.
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
    )
)


def _is_private_network(address: str) -> bool:
    """True when ``address`` is loopback or on a private network.

    An IPv4-mapped IPv6 address is judged by the IPv4 address it carries:
    ``::ffff:10.0.0.5`` is private and ``::ffff:8.8.8.8`` is not.
    """
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in network for network in _PRIVATE_NETWORKS)


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
    #: Every resolved address must be loopback or on a private network (see
    #: ``_PRIVATE_NETWORKS``). Set for `local` while SAG_LOCAL_ROUTING is on,
    #: where `local` has to be the operator's own model rather than a name.
    require_private_network: bool = False

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
            # Every address, not the first: a name that resolves to one private
            # and one public address is one connection away from the public one.
            if self.require_private_network and not _is_private_network(address):
                raise EgressBlockedError(
                    f"destination {self.name!r}: {host!r} resolves to {address}, which is not "
                    "loopback or a private network; SAG_LOCAL_ROUTING requires the local "
                    "model on your own network"
                )
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
            "require_private_network": self.require_private_network,
        }


def policy_for(
    destination: str,
    *,
    allowed_hosts: frozenset[str] = frozenset(),
    allow_private_override: bool | None = None,
    require_private_network: bool = False,
) -> EgressPolicy:
    """The default policy for a named destination.

    ``local`` allows private addresses because that is what it is for; every
    other destination does not. An operator can override globally, and the
    override is logged loudly because it removes the SSRF control.

    ``require_private_network`` is stricter than both: the destination may
    resolve *only* to loopback or private networks. Private addresses are then
    allowed by construction, since they are the only ones left.
    """
    if require_private_network:
        return EgressPolicy(
            name=destination,
            allow_private=True,
            allowed_hosts=allowed_hosts,
            require_private_network=True,
        )

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
