from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

RISK = {
    "read_record": "low",
    "draft_message": "medium",
    "send_message": "high",
    "delete_record": "forbidden",
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    state: str
    reason: str
    audit_id: str


def authorize(
    tool: str,
    scopes: set[str],
    *,
    dry_run: bool,
    approval: str | None = None,
    idempotency_key: str | None = None,
) -> Decision:
    risk = RISK.get(tool, "forbidden")
    audit = sha256(f"{tool}|{sorted(scopes)}|{dry_run}|{idempotency_key}".encode()).hexdigest()[:12]
    if risk == "forbidden":
        return Decision(False, "blocked", "tool is not allowlisted", audit)
    if tool not in scopes:
        return Decision(False, "blocked", "scope missing", audit)
    if dry_run:
        return Decision(True, "preview", "no side effect authorized", audit)
    if risk == "high" and approval != f"approve:{tool}":
        return Decision(False, "review", "exact approval required", audit)
    if risk in {"medium", "high"} and not idempotency_key:
        return Decision(False, "blocked", "idempotency key required", audit)
    return Decision(True, "execute", "policy satisfied", audit)
