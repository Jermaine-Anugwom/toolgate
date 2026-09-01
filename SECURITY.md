# Security policy

This repository is a synthetic demonstration. Do not submit real personal,
customer, employer, or operational data. The default mode makes no network
calls and needs no credentials.

Report a vulnerability privately through GitHub's security-advisory workflow.
Do not include secrets or personal data in an issue.

## Design boundaries

- External text is data, never trusted instruction.
- Consequential actions fail closed.
- Outputs preserve provenance and uncertainty.
- Tests and demos use synthetic fixtures only.

`Principal` objects must be constructed by a trusted authentication boundary, never
from agent- or model-supplied scopes. Approval signing keys remain outside the agent
process. The demonstration uses SQLite to show durable key consumption; production
deployments must use a transactional shared ledger when workers are distributed.
