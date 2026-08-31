import pytest

from toolgate.core import authorize


@pytest.mark.parametrize("tool", ["delete_record", "unknown", "shell", "wire_money"])
def test_forbidden(tool):
    assert authorize(tool, {tool}, dry_run=False).state == "blocked"


@pytest.mark.parametrize("tool", ["read_record", "draft_message", "send_message"])
def test_scope(tool):
    assert authorize(tool, set(), dry_run=True).reason == "scope missing"


def test_dry_run():
    assert authorize("send_message", {"send_message"}, dry_run=True).state == "preview"


def test_high_risk_approval():
    assert (
        authorize("send_message", {"send_message"}, dry_run=False, idempotency_key="1").state
        == "review"
    )


def test_exact_approval():
    assert authorize(
        "send_message",
        {"send_message"},
        dry_run=False,
        approval="approve:send_message",
        idempotency_key="1",
    ).allowed


def test_medium_requires_key():
    assert not authorize("draft_message", {"draft_message"}, dry_run=False).allowed


def test_read_executes():
    assert authorize("read_record", {"read_record"}, dry_run=False).state == "execute"


def test_audit_deterministic():
    assert (
        authorize("read_record", {"read_record"}, dry_run=True).audit_id
        == authorize("read_record", {"read_record"}, dry_run=True).audit_id
    )
