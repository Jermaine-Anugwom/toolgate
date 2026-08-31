# ToolGate runbook

1. Create a Python 3.12 virtual environment.
2. Install with `python -m pip install -e '.[dev]'`.
3. Run `pytest -q` and confirm the deterministic suite is green.
4. Run the documented demo command from the README.
5. Inspect explicit `review`, `blocked`, or `abstain` states before changing policy.

## Recovery

Stop the process, preserve its audit output, restore the last known configuration,
and rerun the failing fixture. Never retry an external side effect without an
idempotency key and authoritative state check.
