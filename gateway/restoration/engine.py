"""Restore only request-minted tokens from the caller's scoped vault."""

from __future__ import annotations

from dataclasses import dataclass, field

from gateway.domain import RequestContext
from gateway.transformations.tokens import TOKEN_PATTERN, TokenProvenance
from gateway.vault.store import (
    CrossTenantAccessError,
    SurrogateVault,
    VaultKeyUnavailableError,
)

MAX_RESTORED_CONTENT_BYTES = 8 * 1024 * 1024


class RestorationOutputTooLargeError(Exception):
    """Restoring valid tokens would exceed the buffered response budget."""


@dataclass(slots=True)
class RestorationOutcome:
    """Auditable record of what restoration did and refused to do."""

    text: str
    restored: int = 0
    #: Token was minted by this request, but the vault has no value for it --
    #: expired, swept, or lost to a restart.
    refused_unknown: int = 0
    #: Token was not minted by this request. Attacker-supplied, hallucinated, or
    #: legitimately replayed from an earlier turn. All three are refused
    #: identically because we cannot tell them apart and do not need to.
    refused_not_minted: int = 0
    #: The vault held a record for another tenant or conversation.
    refused_cross_tenant: int = 0
    #: The record names a key version the operator has not configured. A
    #: configuration error, not an attack -- and it must not look like one.
    refused_key_unavailable: int = 0
    refused_tokens: list[str] = field(default_factory=list)

    @property
    def total_refused(self) -> int:
        return (
            self.refused_unknown
            + self.refused_not_minted
            + self.refused_cross_tenant
            + self.refused_key_unavailable
        )

    def reasons(self) -> dict[str, int]:
        """Non-zero refusal counts by reason, for the audit event."""
        counts = {
            "not_minted": self.refused_not_minted,
            "vault_miss": self.refused_unknown,
            "cross_tenant": self.refused_cross_tenant,
            "key_unavailable": self.refused_key_unavailable,
        }
        return {reason: count for reason, count in counts.items() if count}

    def merge(self, other: RestorationOutcome) -> None:
        """Accumulate another field's outcome into this one."""
        self.restored += other.restored
        self.refused_unknown += other.refused_unknown
        self.refused_not_minted += other.refused_not_minted
        self.refused_cross_tenant += other.refused_cross_tenant
        self.refused_key_unavailable += other.refused_key_unavailable
        self.refused_tokens.extend(other.refused_tokens)


class RestorationEngine:
    def __init__(
        self,
        vault: SurrogateVault,
        max_output_bytes: int = MAX_RESTORED_CONTENT_BYTES,
    ) -> None:
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        self._vault = vault
        self._max_output_bytes = max_output_bytes

    @property
    def vault(self) -> SurrogateVault:
        """The vault this engine reads from.

        Exposed so the application can run the expiry sweep and answer deletion
        requests without a second construction path that could diverge on
        configuration.
        """
        return self._vault

    @property
    def max_output_bytes(self) -> int:
        return self._max_output_bytes

    def restore(
        self,
        ctx: RequestContext,
        text: str,
        provenance: TokenProvenance,
        max_output_bytes: int | None = None,
    ) -> RestorationOutcome:
        """Restore only tokens this request minted and the vault confirms."""
        budget = self._max_output_bytes if max_output_bytes is None else max_output_bytes
        if budget < 0:
            raise ValueError("max_output_bytes cannot be negative")
        outcome = RestorationOutcome(text=text)

        matches = list(TOKEN_PATTERN.finditer(text))
        if not matches:
            if len(text.encode("utf-8")) > budget:
                raise RestorationOutputTooLargeError(f"restored content exceeds {budget} bytes")
            return outcome

        # Keep right-to-left lookup/refusal ordering, then assemble once. This
        # avoids copying the growing result once per token.
        fragments: list[str] = []
        cursor = len(text)
        projected_bytes = len(text.encode("utf-8"))
        for match in reversed(matches):
            token = match.group(0)
            token_version = match.group(2)
            replacement = token

            if not provenance.was_minted_here(token):
                outcome.refused_not_minted += 1
                outcome.refused_tokens.append(token)
            else:
                try:
                    value = self._vault.get(ctx, token, token_version)
                except CrossTenantAccessError:
                    outcome.refused_cross_tenant += 1
                    outcome.refused_tokens.append(token)
                except VaultKeyUnavailableError:
                    outcome.refused_key_unavailable += 1
                    outcome.refused_tokens.append(token)
                else:
                    if value is None:
                        outcome.refused_unknown += 1
                        outcome.refused_tokens.append(token)
                    else:
                        replacement = value
                        outcome.restored += 1
                        projected_bytes += len(value.encode("utf-8")) - len(token)

            fragments.extend((text[match.end() : cursor], replacement))
            cursor = match.start()

        fragments.append(text[:cursor])
        if projected_bytes > budget:
            raise RestorationOutputTooLargeError(f"restored content exceeds {budget} bytes")
        fragments.reverse()
        outcome.text = "".join(fragments)
        return outcome
