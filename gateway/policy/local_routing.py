"""Local routing: the routing floor behind SAG_LOCAL_ROUTING ("GDPR mode").

``off`` leaves routing to the policy. ``detected`` sends a request in which any
detector found anything only to the `local` destination. ``all`` sends every
request that is not blocked there. See
docs/adr/0017-local-routing-mode.md.

The floor is applied to the *composed* decision -- after the YAML policy and
the operator's filters -- and it keys on two things only: whether inspection
found a span, and whether the destination is exactly ``local``. It never reads
an entity type, a rule's order, or a ``min_score``, which is how the enumerated
preset it replaces was routed around: a type the list did not name, a span that
won conflict resolution under another label, a filter that outranked the list,
a span scored below a threshold. A ``route_local`` rule whose destination fell
back to ``default_destination`` is caught by the exact destination check.

What it never does:

* **Weaken a block.** BLOCK is returned untouched, so the mode can only move a
  request, never release one (SI-10).
* **Change a decision that is already local.** ``route_local`` and
  ``transform`` keep pseudonymising, and an operator's explicit ``allow`` to
  their own model keeps its action.

A moved request takes the existing ``route_local`` path, so the local model
receives tokens, not raw values. That is pseudonymisation, and nothing here
may be described as anonymisation.

This is the enforcement for SI-01 under the mode. The pipeline checks again
before it sends (SI-14), by provider identity and with its own reading of the
mode rather than a call to ``requires_local``, so a regression in the rewrite
or in that predicate fails closed there rather than routing externally.
"""

from __future__ import annotations

import enum

from gateway.domain import Action, InspectionResult, PolicyDecision

#: The only destination the mode accepts, compared exactly. ``Local``,
#: ``local `` and an empty destination are different names and are rewritten.
LOCAL_DESTINATION = "local"


class LocalRoutingViolation(Exception):
    """The mode requires `local`, and another provider was about to be called.

    Unreachable while the engine applies :func:`apply_local_routing`. Raised by
    the pipeline's provider-identity check if that ever regresses, before
    anything is sent.
    """


class LocalRouting(enum.StrEnum):
    OFF = "off"
    DETECTED = "detected"
    ALL = "all"

    @classmethod
    def parse(cls, raw: str) -> LocalRouting:
        """Strict: empty means ``off``, and anything unrecognised is an error.

        ``on``, ``true`` or ``gdpr`` must never quietly read as ``off``: an
        operator would believe the mode is on while every request is routed as
        before.
        """
        try:
            return cls(raw.strip().lower() or "off")
        except ValueError:
            valid = ", ".join(member.value for member in cls)
            raise ValueError(f"SAG_LOCAL_ROUTING must be one of: {valid}") from None

    def requires_local(self, inspection: InspectionResult) -> bool:
        """Whether this request may reach no destination but `local`."""
        return self is LocalRouting.ALL or (
            self is LocalRouting.DETECTED and bool(inspection.spans)
        )

    def required_destinations(self, selectable: frozenset[str]) -> frozenset[str]:
        """The destinations startup must find configured under this mode.

        ``selectable`` is what the policy's own rules can name. Under ``all``
        none of them can be reached any more, so only `local` is required.
        """
        if self is LocalRouting.ALL:
            return frozenset({LOCAL_DESTINATION})
        if self is LocalRouting.DETECTED:
            return selectable | {LOCAL_DESTINATION}
        return selectable


def apply_local_routing(
    mode: LocalRouting, decision: PolicyDecision, inspection: InspectionResult
) -> PolicyDecision:
    """Move ``decision`` to `local` when the mode requires it. Pure and total."""
    if (
        decision.action is Action.BLOCK
        or decision.destination == LOCAL_DESTINATION
        or not mode.requires_local(inspection)
    ):
        return decision
    return PolicyDecision(
        action=Action.ROUTE_LOCAL,
        destination=LOCAL_DESTINATION,
        rule_name=f"local-routing:{mode}",
        policy_version=decision.policy_version,
        matched_entities=tuple(sorted(inspection.entity_types())),
        reason=(
            f"local routing {mode} replaced rule {decision.rule_name!r} "
            f"({decision.action}, destination {decision.destination!r})"
        ),
    )
