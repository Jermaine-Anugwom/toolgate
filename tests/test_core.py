from __future__ import annotations

import pytest

from toolgate.core import (
    Approval,
    ApprovalAuthority,
    IdempotencyLedger,
    Principal,
    authorize,
)


def principal(*scopes: str) -> Principal:
    return Principal("synthetic-agent", frozenset(scopes))


@pytest.mark.parametrize("tool", ["delete_record", "unknown", "shell", "wire_money"])
def test_forbidden(tool):
    assert authorize(tool, principal(tool), dry_run=False).state == "blocked"


@pytest.mark.parametrize("tool", ["read_record", "draft_message", "send_message"])
def test_trusted_scope(tool):
    assert authorize(tool, principal(), dry_run=True).reason == "trusted principal scope missing"


def test_dry_run():
    assert authorize("send_message", principal("send_message"), dry_run=True).state == "preview"


def test_high_risk_requires_bound_approval():
    result = authorize(
        "send_message",
        principal("send_message"),
        {"recipient": "synthetic@example.test"},
        dry_run=False,
        idempotency_key="1",
    )
    assert result.state == "review"


def test_bound_approval_executes_once(tmp_path):
    identity = principal("send_message")
    arguments = {"recipient": "synthetic@example.test", "body": "hello"}
    authority = ApprovalAuthority(b"synthetic-test-signing-key")
    ledger = IdempotencyLedger(str(tmp_path / "claims.db"))
    approval = authority.issue(identity, "send_message", arguments, "1", "operator", 200)
    first = authorize(
        "send_message",
        identity,
        arguments,
        dry_run=False,
        approval=approval,
        authority=authority,
        ledger=ledger,
        idempotency_key="1",
        now=100,
    )
    second = authorize(
        "send_message",
        identity,
        arguments,
        dry_run=False,
        approval=approval,
        authority=authority,
        ledger=ledger,
        idempotency_key="1",
        now=100,
    )
    assert first.allowed and second.state == "duplicate" and not second.allowed


def test_approval_is_bound_to_arguments():
    identity = principal("send_message")
    authority = ApprovalAuthority(b"synthetic-test-signing-key")
    approval = authority.issue(identity, "send_message", {"body": "approved"}, "1", "operator", 200)
    result = authorize(
        "send_message",
        identity,
        {"body": "changed"},
        dry_run=False,
        approval=approval,
        authority=authority,
        ledger=IdempotencyLedger(),
        idempotency_key="1",
        now=100,
    )
    assert result.state == "review"


def test_expired_approval_is_rejected():
    identity = principal("send_message")
    authority = ApprovalAuthority(b"synthetic-test-signing-key")
    approval = authority.issue(identity, "send_message", {}, "1", "operator", 99)
    result = authorize(
        "send_message",
        identity,
        {},
        dry_run=False,
        approval=approval,
        authority=authority,
        ledger=IdempotencyLedger(),
        idempotency_key="1",
        now=100,
    )
    assert result.state == "review"


def test_forged_approval_is_rejected():
    identity = principal("send_message")
    authority = ApprovalAuthority(b"synthetic-test-signing-key")
    forged = Approval(
        identity.principal_id, "send_message", "0" * 64, "1", 200, "operator", "0" * 64
    )
    result = authorize(
        "send_message",
        identity,
        {},
        dry_run=False,
        approval=forged,
        authority=authority,
        ledger=IdempotencyLedger(),
        idempotency_key="1",
        now=100,
    )
    assert result.state == "review"


def test_medium_requires_key_and_ledger():
    identity = principal("draft_message")
    assert not authorize("draft_message", identity, dry_run=False).allowed
    result = authorize("draft_message", identity, dry_run=False, idempotency_key="1")
    assert result.reason == "idempotency ledger required"


def test_read_executes_without_side_effect_ledger():
    assert authorize("read_record", principal("read_record"), dry_run=False).state == "execute"


def test_audit_is_deterministic():
    identity = principal("read_record")
    assert (
        authorize("read_record", identity, dry_run=True).audit_id
        == authorize("read_record", identity, dry_run=True).audit_id
    )
