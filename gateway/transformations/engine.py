"""Replace detected spans with scoped surrogate tokens."""

from __future__ import annotations

from dataclasses import dataclass

from gateway.detectors.base import resolve_conflicts
from gateway.domain import RequestContext, Span
from gateway.transformations.tokens import TokenMinter, TokenProvenance
from gateway.vault.store import SurrogateVault


@dataclass(slots=True)
class TransformationResult:
    text: str
    provenance: TokenProvenance
    replaced: int


class TransformationEngine:
    def __init__(self, minter: TokenMinter, vault: SurrogateVault) -> None:
        self._minter = minter
        self._vault = vault

    def transform(
        self,
        ctx: RequestContext,
        text: str,
        spans: list[Span],
        provenance: TokenProvenance | None = None,
    ) -> TransformationResult:
        """Replace each span with its surrogate token.

        ``provenance`` may be supplied to accumulate across several fields of
        one request (system prompt, each message, tool arguments) so the same
        value gets the same token everywhere in the request -- which is what
        makes the model able to reason about identity at all.
        """
        prov = provenance if provenance is not None else TokenProvenance()

        if not spans:
            return TransformationResult(text=text, provenance=prov, replaced=0)

        ordered = resolve_conflicts(spans)

        # Mint right-to-left to preserve the established canonical-value
        # behavior, but assemble once. Repeated slicing here used to copy the
        # whole output for every match.
        fragments: list[str] = []
        cursor = len(text)
        for span in reversed(ordered):
            surrogate = self._minter.mint(ctx, span.entity_type, span.text, prov)
            self._vault.put(ctx, surrogate.token, surrogate.original_value, surrogate.version)
            fragments.extend((text[span.end : cursor], surrogate.token))
            cursor = span.start

        fragments.append(text[:cursor])
        fragments.reverse()
        result = "".join(fragments)

        return TransformationResult(text=result, provenance=prov, replaced=len(ordered))
