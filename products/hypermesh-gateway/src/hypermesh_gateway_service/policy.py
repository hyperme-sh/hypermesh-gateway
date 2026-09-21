"""Door-side org policy. Same specificity as the AIuditor plane.

A miss is not a deny. Renter/service default allow (unclassified).
IR default is the taxonomy decision. Closed inbox returns no rows.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

POLICY_PURPOSES = frozenset({"renter", "ir", "service"})


@dataclass(frozen=True)
class PolicyView:
    purpose: str
    disposition: str
    prompt_class: str | None = None
    connection_id: uuid.UUID | None = None


def _score(
    row: PolicyView,
    *,
    purpose: str,
    prompt_class: str | None,
    connection_id: uuid.UUID | None,
) -> int:
    if row.purpose != purpose:
        return 0
    if row.connection_id is not None and row.connection_id != connection_id:
        return 0
    if row.prompt_class is not None and row.prompt_class != prompt_class:
        return 0
    score = 1
    if row.prompt_class is not None:
        score += 2
    if row.connection_id is not None:
        score += 4
    return score


def decide_policy(
    purpose: str,
    policies: list[PolicyView],
    *,
    prompt_class: str | None,
    taxonomy_decision: str,
    connection_id: uuid.UUID | None = None,
) -> str:
    """allow, hold, or deny."""

    best: PolicyView | None = None
    best_score = 0
    for row in policies:
        score = _score(
            row,
            purpose=purpose,
            prompt_class=prompt_class,
            connection_id=connection_id,
        )
        if score > best_score:
            best = row
            best_score = score
    if best is not None:
        return best.disposition
    if purpose == "ir":
        return taxonomy_decision
    return "allow"


def policy_needs_classify(policies: list[PolicyView]) -> bool:
    """Class-scoped or hold rules need a class. Purpose-wide deny does not."""

    return any(row.prompt_class or row.disposition == "hold" for row in policies)
