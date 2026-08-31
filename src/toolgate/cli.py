from __future__ import annotations

import json
from dataclasses import asdict

from .core import authorize


def main() -> None:
    preview = authorize("send_message", {"send_message"}, dry_run=True, idempotency_key="SYN-01")
    print(json.dumps({"synthetic": True, "decision": asdict(preview)}, indent=2))
