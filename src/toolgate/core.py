from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from time import time
from typing import Any

RISK = {
    "read_record": "low",
    "draft_message": "medium",
    "send_message": "high",
    "delete_record": "forbidden",
}


@dataclass(frozen=True)
class Principal:
    principal_id: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    state: str
    reason: str
    audit_id: str


@dataclass(frozen=True)
class Approval:
    principal_id: str
    tool: str
    arguments_hash: str
    idempotency_key: str
    expires_at: int
    approved_by: str
    signature: str


def arguments_hash(arguments: dict[str, Any]) -> str:
    encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(encoded.encode()).hexdigest()


class ApprovalAuthority:
    """Trusted operator boundary, separate from the agent requesting a tool."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 16:
            raise ValueError("signing key must contain at least 16 bytes")
        self._signing_key = signing_key

    def issue(
        self,
        principal: Principal,
        tool: str,
        arguments: dict[str, Any],
        idempotency_key: str,
        approved_by: str,
        expires_at: int,
    ) -> Approval:
        digest = arguments_hash(arguments)
        payload = "|".join(
            (principal.principal_id, tool, digest, idempotency_key, str(expires_at), approved_by)
        ).encode()
        signature = hmac_new(self._signing_key, payload, "sha256").hexdigest()
        return Approval(
            principal.principal_id,
            tool,
            digest,
            idempotency_key,
            expires_at,
            approved_by,
            signature,
        )

    def verifies(
        self,
        approval: Approval,
        principal: Principal,
        tool: str,
        arguments: dict[str, Any],
        idempotency_key: str,
        now: int,
    ) -> bool:
        expected = self.issue(
            principal,
            tool,
            arguments,
            idempotency_key,
            approval.approved_by,
            approval.expires_at,
        )
        return (
            approval.principal_id == principal.principal_id
            and approval.tool == tool
            and approval.arguments_hash == arguments_hash(arguments)
            and approval.idempotency_key == idempotency_key
            and approval.expires_at >= now
            and compare_digest(approval.signature, expected.signature)
        )


class IdempotencyLedger:
    """SQLite-backed claim ledger; a key can be consumed only once."""

    def __init__(self, database: str = ":memory:") -> None:
        self._connection = sqlite3.connect(database)
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS claims (key TEXT PRIMARY KEY, audit_id TEXT NOT NULL)"
        )
        self._connection.commit()

    def claim(self, key: str, audit_id: str) -> bool:
        try:
            with self._connection:
                self._connection.execute(
                    "INSERT INTO claims (key, audit_id) VALUES (?, ?)", (key, audit_id)
                )
        except sqlite3.IntegrityError:
            return False
        return True


def authorize(
    tool: str,
    principal: Principal,
    arguments: dict[str, Any] | None = None,
    *,
    dry_run: bool,
    approval: Approval | None = None,
    authority: ApprovalAuthority | None = None,
    ledger: IdempotencyLedger | None = None,
    idempotency_key: str | None = None,
    now: int | None = None,
) -> Decision:
    arguments = arguments or {}
    current_time = int(time()) if now is None else now
    risk = RISK.get(tool, "forbidden")
    audit = sha256(
        f"{principal.principal_id}|{tool}|{arguments_hash(arguments)}|{dry_run}|{idempotency_key}".encode()
    ).hexdigest()[:12]
    if risk == "forbidden":
        return Decision(False, "blocked", "tool is not allowlisted", audit)
    if tool not in principal.scopes:
        return Decision(False, "blocked", "trusted principal scope missing", audit)
    if dry_run:
        return Decision(True, "preview", "no side effect authorized", audit)
    if risk in {"medium", "high"} and not idempotency_key:
        return Decision(False, "blocked", "idempotency key required", audit)
    if risk == "high" and (
        approval is None
        or authority is None
        or not authority.verifies(
            approval, principal, tool, arguments, idempotency_key, current_time
        )
    ):
        return Decision(False, "review", "valid bound approval required", audit)
    if risk in {"medium", "high"} and ledger is None:
        return Decision(False, "blocked", "idempotency ledger required", audit)
    if risk in {"medium", "high"} and not ledger.claim(idempotency_key, audit):
        return Decision(False, "duplicate", "idempotency key already claimed", audit)
    return Decision(True, "execute", "policy satisfied", audit)
