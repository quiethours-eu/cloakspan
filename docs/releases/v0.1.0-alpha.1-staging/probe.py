"""Black-box checks against a running gateway for the staging rehearsal.

Stdlib only. Reads secrets from the Compose .env file and never prints them.
Prints one PASS/FAIL line per check and exits non-zero if any check failed.
All request content is synthetic.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

EMAIL = "jana.berzina@example.test"
IBAN = "LV80BANK0000435195001"
SECRET = "AKIAIOSFODNN7EXAMPLE"
CONVERSATION = "rehearsal-conv-1"

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    results.append((bool(ok), name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}".rstrip(), flush=True)
    return bool(ok)


def _lower(headers):
    return {name.lower(): value for name, value in headers.items()}


def http(method, url, *, headers=None, data=None, timeout=30):
    request = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, _lower(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, _lower(exc.headers), exc.read()
    except (urllib.error.URLError, OSError) as exc:
        return 0, {}, str(type(exc).__name__).encode()


def chat(base, key, content, *, conversation=None, raw=None, timeout=30):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if conversation:
        headers["X-Conversation-Id"] = conversation
    body = raw
    if body is None:
        body = json.dumps(
            {"model": "rehearsal-model", "messages": [{"role": "user", "content": content}]}
        ).encode()
    return http(
        "POST", f"{base}/v1/chat/completions", headers=headers, data=body, timeout=timeout
    )


def reply_text(body: bytes) -> str:
    try:
        return json.loads(body)["choices"][0]["message"]["content"]
    except Exception:
        return ""


def error_code(body: bytes) -> str:
    try:
        return str(json.loads(body)["error"].get("code"))
    except Exception:
        return "?"


def mock_seen(mock) -> list[dict]:
    status, _, body = http("GET", f"{mock}/_requests")
    return json.loads(body) if status == 200 else []


def basic(args, env, state) -> None:
    base, mock, key = args.base, args.mock, env["KEY_A"]
    status, _, _ = http("GET", f"{base}/healthz")
    check(status == 200, "healthz", f"status={status}")
    status, _, _ = http("GET", f"{base}/readyz")
    check(status == 200, "readyz", f"status={status}")

    status, _, body = chat(base, None, "hello")
    check(status == 401, "no credential is refused", f"status={status}")
    status, _, body = chat(base, "sgw_live_" + "0" * 40, "hello")
    check(status == 401, "unknown key is refused", f"status={status}")

    http("POST", f"{mock}/_reset", data=b"{}")
    status, headers, body = chat(base, key, "Summarise the weather in one line.")
    check(
        status == 200 and len(mock_seen(mock)) == 1,
        "clean request is forwarded",
        f"status={status} decision={headers.get('x-policy-decision')}",
    )

    http("POST", f"{mock}/_reset", data=b"{}")
    prompt = f"Write to {EMAIL} about the transfer to {IBAN}."
    status, headers, body = chat(base, key, prompt, conversation=CONVERSATION)
    seen = mock_seen(mock)
    upstream = json.dumps(seen)
    check(
        status == 200 and len(seen) == 1 and EMAIL not in upstream and IBAN not in upstream,
        "sensitive values are replaced before the provider",
        f"status={status} decision={headers.get('x-policy-decision')} "
        f"entities={headers.get('x-entities-detected')}",
    )
    text = reply_text(body)
    check(
        EMAIL in text and IBAN in text,
        "tokens are restored in the reply",
        f"restored={headers.get('x-tokens-restored')} refused={headers.get('x-tokens-refused')}",
    )
    if seen:
        state[f"upstream_content:{args.phase}"] = seen[0]["messages"][-1]["content"]

    http("POST", f"{mock}/_reset", data=b"{}")
    status, headers, body = chat(base, key, f"Example credential: {SECRET}.")
    check(
        status == 403 and not mock_seen(mock),
        "credential is blocked and nothing is forwarded",
        f"status={status} code={error_code(body)}",
    )

    http("POST", f"{mock}/_reset", data=b"{}")
    big = json.dumps(
        {"model": "rehearsal-model", "messages": [{"role": "user", "content": "x" * 1_200_000}]}
    ).encode()
    status, _, body = chat(base, key, None, raw=big)
    check(
        status == 413 and not mock_seen(mock),
        "oversized body is refused",
        f"status={status} code={error_code(body)}",
    )
    status, _, body = chat(base, key, None, raw=b'{"model": ')
    check(status == 400, "malformed JSON is refused", f"status={status}")


def old_token(args, env, state) -> None:
    """A token minted by the previous process must not be restored by this one."""
    content = state.get(f"upstream_content:{args.old_from}")
    if not check(bool(content), "old tokenised content is available", f"from={args.old_from}"):
        return
    status, headers, body = chat(args.base, env["KEY_A"], content, conversation=CONVERSATION)
    text = reply_text(body) + body.decode("utf-8", "replace")
    check(
        EMAIL not in text and IBAN not in text,
        "tokens from the previous process are not restored",
        f"status={status} restored={headers.get('x-tokens-restored')} "
        f"refused={headers.get('x-tokens-refused')} code={error_code(body) if status >= 400 else '-'}",
    )


def new_features(args, env, state) -> None:
    base, key = args.base, env["KEY_A"]
    status, headers, _ = http("GET", f"{base}/metrics")
    check(status == 401, "metrics without a token is refused", f"status={status}")
    status, _, _ = http("GET", f"{base}/metrics", headers={"Authorization": f"Bearer {key}"})
    check(status == 401, "metrics refuses a tenant API key", f"status={status}")
    status, _, body = http(
        "GET", f"{base}/metrics", headers={"Authorization": f"Bearer {env['SAG_METRICS_TOKEN']}"}
    )
    text = body.decode("utf-8", "replace")
    check(
        status == 200 and "cloakspan_requests_total" in text,
        "metrics with its token is served",
        f"status={status} lines={len(text.splitlines())}",
    )
    leaked = [v for v in (EMAIL, IBAN, SECRET, CONVERSATION, "rehearsal-model") if v in text]
    check(not leaked, "metrics carry no request content", f"leaked={len(leaked)}")

    limit = int(env.get("SAG_RATE_LIMIT_PER_MINUTE", "600"))
    statuses, retry_after = [], None
    for _ in range(limit + 15):
        status, headers, _ = chat(base, env["KEY_B"], "ping")
        statuses.append(status)
        if status == 429:
            retry_after = headers.get("retry-after")
            break
    check(
        statuses[-1] == 429 and bool(retry_after),
        "rate limit refuses with 429 and Retry-After",
        f"admitted={statuses.count(200)} limit={limit} retry_after={retry_after}",
    )
    status, headers, _ = chat(base, key, "ping")
    request_id = headers.get("x-request-id")
    check(status == 200, "another key is unaffected by that limit", f"status={status}")
    check(bool(request_id), "responses carry X-Request-Id")


def previous_version(args, env, state) -> None:
    status, _, _ = http("GET", f"{args.base}/metrics")
    check(status == 404, "previous version has no metrics route", f"status={status}")


def provider_down(args, env, state) -> None:
    base, key = args.base, env["KEY_A"]
    status, _, body = chat(base, key, f"Write to {EMAIL}.", timeout=150)
    check(
        500 <= status < 600 and EMAIL not in body.decode("utf-8", "replace"),
        "provider outage gives a 5xx error, not a hang or a leak",
        f"status={status} code={error_code(body)}",
    )
    status, _, _ = http("GET", f"{base}/readyz")
    check(status == 200, "readyz stays 200 during the provider outage", f"status={status}")
    status, _, body = chat(base, key, f"Example credential: {SECRET}.")
    check(status == 403, "blocking still works during the provider outage", f"status={status}")


CHECKS = {
    "basic": basic,
    "old_token": old_token,
    "new": new_features,
    "prev": previous_version,
    "provider_down": provider_down,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--mock", required=True)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--old-from", default="")
    parser.add_argument("--checks", required=True)
    args = parser.parse_args()

    env: dict[str, str] = {}
    for line in Path(args.env_file).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            name, _, value = line.partition("=")
            env[name.strip()] = value.strip()
    keys = [item.split(":")[0] for item in env["SAG_API_KEYS"].split(",")]
    env["KEY_A"], env["KEY_B"] = keys[0], keys[1]

    state_path = Path(args.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    print(f"== probe phase={args.phase} checks={args.checks}", flush=True)
    for name in args.checks.split(","):
        CHECKS[name](args, env, state)
    state_path.write_text(json.dumps(state))
    failed = [name for ok, name, _ in results if not ok]
    print(f"== {len(results) - len(failed)}/{len(results)} passed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
