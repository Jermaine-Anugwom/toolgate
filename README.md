# ToolGate

**Permissioned agent tools with dry runs, approvals, and replay safety.**

> All people, organizations, records, measurements, and outcomes in this
> repository are synthetic.

## The operational problem

Agents should not turn a plausible plan into an irreversible external action without policy controls.

## The proof

Scoped capabilities, risk classification, approval tokens, idempotency keys, and audit records.

## Why this is forward deployed

The project begins with the operator's decision, uncertainty, failure cost,
integration boundary, and handoff—not with a model demo. It makes policy and
evidence inspectable, preserves human authority for consequential cases, and
remains useful when the optional model layer is unavailable.

## Architecture

```mermaid
flowchart LR
  A[Agent tool request] --> B[Allowlist + scope]
  B --> C{Risk class}
  C -->|forbidden| D[Block]
  C -->|high| E[Exact approval]
  C -->|safe preview| F[Dry run]
  E --> G[Idempotency gate]
  G --> H[Execute + audit ID]
```

## Quickstart

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
toolgate
```

No API key or network connection is required.

## Evaluation and limitations

Run `pytest -q` for the reproducible evaluation. The fixture set is deliberately
synthetic and cannot establish production performance. A real deployment would
require operator observation, representative data, policy review, privacy review,
security testing, and a monitored rollout.

## Project documents

- [Field discovery and handoff](FIELD_NOTES.md)
- [Security boundaries](SECURITY.md)
- [Operating runbook](RUNBOOK.md)
- [Development provenance](DEVELOPMENT.md)
- [Release history](CHANGELOG.md)

## Topics

`ai-agents`, `authorization`, `human-in-the-loop`, `security`, `python`
