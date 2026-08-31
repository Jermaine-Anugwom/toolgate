# Field notes

## Operator problem

Agents should not turn a plausible plan into an irreversible external action without policy controls.

## Discovery questions

- Who owns the decision when automation is uncertain?
- Which source is authoritative when records disagree?
- What must remain usable during a provider or network outage?
- Which false positive creates the greatest operational harm?
- What evidence will an operator need to challenge a result?

## Constraints

- Synthetic data only.
- Deterministic offline operation is the baseline.
- Unresolved consequential decisions enter review rather than being guessed.
- Logs explain inputs, policy, output, and next safe action.

## Success measure

Scoped capabilities, risk classification, approval tokens, idempotency keys, and audit records.

## Handoff

A customer team receives the operating assumptions, configuration surface,
test suite, runbook, known limitations, and rollback path—not merely source
code or a demonstration.
