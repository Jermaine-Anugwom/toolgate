from __future__ import annotations

import json
from dataclasses import asdict

from .core import ApprovalAuthority, IdempotencyLedger, Principal, authorize


def main() -> None:
    principal = Principal("synthetic-agent", frozenset({"send_message"}))
    arguments = {"recipient": "operator@example.test", "body": "Synthetic status update"}
    authority = ApprovalAuthority(b"synthetic-operator-boundary-key")
    approval = authority.issue(principal, "send_message", arguments, "SYN-01", "operator", 200)
    decision = authorize(
        "send_message",
        principal,
        arguments,
        dry_run=False,
        approval=approval,
        authority=authority,
        ledger=IdempotencyLedger(),
        idempotency_key="SYN-01",
        now=100,
    )
    print(json.dumps({"synthetic": True, "decision": asdict(decision)}, indent=2))
