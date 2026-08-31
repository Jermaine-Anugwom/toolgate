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
