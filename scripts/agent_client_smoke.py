from __future__ import annotations

import argparse
import os
import sys

import httpx


def main() -> int:
    parser = argparse.ArgumentParser(description="Small non-agent client for browser handoff service smoke testing.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default=os.environ.get("BROWSER_HANDOFF_SERVICE_TOKEN"))
    parser.add_argument("--url", default="data:text/html,<title>checkout</title><button>Pay</button>")
    args = parser.parse_args()
    if not args.token:
        parser.error("--token or BROWSER_HANDOFF_SERVICE_TOKEN is required")

    headers = {"authorization": f"Bearer {args.token}"}
    with httpx.Client(base_url=args.base_url, timeout=10) as client:
        session = client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_smoke"},
        )
        session.raise_for_status()
        session_id = session.json()["session_id"]

        nav = client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=headers,
            json={"type": "navigate", "args": {"url": args.url}},
        )
        nav.raise_for_status()

        handoff = client.post(
            f"/v1/sessions/{session_id}/handoff",
            headers=headers,
            json={"reason": "payment", "handoff_note": "Complete payment"},
        )
        handoff.raise_for_status()
        token = handoff.json()["handoff_url"].split("token=", 1)[1]

        denied = client.post(f"/v1/sessions/{session_id}/agent-command", headers=headers, json={"type": "snapshot"})
        if denied.status_code != 403:
            raise AssertionError(
                f"expected denied agent command during handoff, got {denied.status_code}: {denied.text}"
            )

        claim = client.post(f"/v1/sessions/{session_id}/claim", json={"token": token})
        claim.raise_for_status()
        control_token = claim.json()["control_token"]

        complete = client.post(
            f"/v1/sessions/{session_id}/complete",
            json={"token": control_token, "outcome": "done"},
        )
        complete.raise_for_status()
        print({"session_id": session_id, "state": complete.json()["state"]})
    return 0


if __name__ == "__main__":
    sys.exit(main())
