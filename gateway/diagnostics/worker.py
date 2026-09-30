"""Disposable subprocess for opt-in operations that can hang or use the network."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path


def _probe(payload: dict[str, object]) -> dict[str, object]:
    import httpx

    from gateway.routing.base import verification_context
    from gateway.routing.egress import policy_for

    name = str(payload["name"])
    url = str(payload["url"])
    policy = policy_for(
        name,
        allowed_hosts=frozenset(str(host) for host in payload["allowed_hosts"]),
        allow_private_override=bool(payload["allow_private"]) or None,
        require_private_network=bool(payload["require_private_network"]),
    )
    try:
        policy.validate(url)
    except Exception:
        return {"outcome": "egress_blocked"}

    headers = {}
    if payload.get("api_key"):
        headers["Authorization"] = f"Bearer {payload['api_key']}"
    try:
        with httpx.Client(
            timeout=float(payload["timeout"]),
            follow_redirects=False,
            trust_env=bool(payload["trust_env"]),
            verify=verification_context(bool(payload["trust_env_certs"])),
        ) as client:
            with client.stream("GET", url.rstrip("/") + "/models", headers=headers) as response:
                status = response.status_code
                if status == 200:
                    size = 0
                    for chunk in response.iter_raw():
                        size += len(chunk)
                        if size > 65536:
                            return {"outcome": "oversized"}
    except httpx.TimeoutException:
        return {"outcome": "timeout"}
    except httpx.TransportError:
        return {"outcome": "connection_failed"}

    if status == 200:
        return {"outcome": "listed"}
    if status in (401, 403):
        return {"outcome": "auth_rejected"}
    if status in (404, 405):
        return {"outcome": "listing_unsupported"}
    if 300 <= status < 400:
        return {"outcome": "redirect"}
    return {"outcome": "http_error"}


def _model(payload: dict[str, object]) -> dict[str, object]:
    from gateway.detectors.ner import LABEL_MAP, NerDetector

    if importlib.util.find_spec("spacy") is None:
        return {"outcome": "dependency_missing"}
    detector = NerDetector.from_directory(Path(str(payload["path"])))
    nlp = detector._backend._nlp  # subprocess-only optional backend inspection
    labels = set()
    if "ner" in nlp.pipe_names:
        labels = set(nlp.get_pipe("ner").labels)
    mapped = sorted({LABEL_MAP[label.upper()] for label in labels if label.upper() in LABEL_MAP})
    observed = sorted(
        {
            span.entity_type
            for span in detector.detect("Alice Example works at Example Corp in Riga.")
        }
    )
    return {
        "outcome": "loaded",
        "backend_mapped_entities": mapped,
        "observed_smoke_entities": observed,
    }


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read())
        operation = payload.get("operation")
        if operation == "probe":
            result = _probe(payload)
        elif operation == "model":
            result = _model(payload)
        else:
            result = {"outcome": "invalid_operation"}
    except Exception:
        result = {"outcome": "worker_failed"}
    # Third-party libraries may write to stdout while loading. The parent
    # reads only the last line and never forwards worker output directly.
    os.write(1, (json.dumps(result, separators=(",", ":")) + "\n").encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
