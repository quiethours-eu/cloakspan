"""Side-effect-free inspection of the gateway's environment.

Only setting names and fixed messages leave this module. Values remain private.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from gateway.auth.keys import KEY_PREFIX
from gateway.crypto import MIN_ROOT_SECRET_BYTES
from gateway.policy.local_routing import LocalRouting


@dataclass(frozen=True, slots=True)
class ConfigIssue:
    id: str
    status: str
    summary: str
    remediation: str
    startup_fatal: bool = True


@dataclass(frozen=True, slots=True)
class ParsedEnvironment:
    numbers: Mapping[str, int | float]
    flags: Mapping[str, bool]
    routing: LocalRouting | None
    issues: tuple[ConfigIssue, ...]


_NUMBERS = {
    "SAG_PORT": (int, 8080, 1, 65535),
    "SAG_VAULT_TTL_SECONDS": (int, 3600, 1, None),
    "SAG_MAX_INPUT_CHARS": (int, 65536, 1, None),
    "SAG_MAX_REQUEST_BYTES": (int, 1048576, 1, None),
    "SAG_REQUEST_TIMEOUT_SECONDS": (float, 120.0, 0, None),
}
_FLAGS = (
    "SAG_TRUST_ENV_PROXY",
    "SAG_BLOCK_MIXED_SCRIPT",
    "SAG_EGRESS_ALLOW_PRIVATE",
)
_TRUE = {"1", "true", "yes"}
_FALSE = {"", "0", "false", "no"}
_VERSIONED = re.compile(r"^SAG_VAULT_KEY_V(\d{1,5})$")


def _issue(
    name: str, problem: str, remedy: str, *, fatal: bool = True, check_id: str | None = None
) -> ConfigIssue:
    return ConfigIssue(
        check_id or name.lower().replace("sag_", "settings.").replace("_", "."),
        "fail",
        problem,
        remedy,
        fatal,
    )


def decode_secret(raw: str) -> bytes:
    """Use the same hex-or-UTF-8 interpretation as gateway startup."""
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


def decoded_secret_length(raw: str) -> int:
    """Inspect a root secret without retaining or publishing its contents."""
    try:
        return len(decode_secret(raw))
    except UnicodeEncodeError:
        return 0


def inspect_environment(env: Mapping[str, str]) -> ParsedEnvironment:
    issues: list[ConfigIssue] = []
    numbers: dict[str, int | float] = {}
    flags: dict[str, bool] = {}

    for name, (kind, default, minimum, maximum) in _NUMBERS.items():
        raw = env.get(name, str(default))
        try:
            value = kind(raw)
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError
            if value < minimum or (minimum == 0 and value == 0):
                raise ValueError
            if maximum is not None and value > maximum:
                raise ValueError
        except (ValueError, OverflowError):
            issues.append(
                _issue(
                    name,
                    f"{name} has an invalid value",
                    f"Set {name} to a finite number in its supported range.",
                )
            )
        else:
            numbers[name] = value

    for name in _FLAGS:
        raw = env.get(name, "").strip().lower()
        if raw not in _TRUE | _FALSE:
            issues.append(
                _issue(name, f"{name} is not a recognized flag", f"Set {name} to true or false.")
            )
        else:
            flags[name] = raw in _TRUE

    try:
        routing = LocalRouting.parse(env.get("SAG_LOCAL_ROUTING", ""))
    except ValueError:
        routing = None
        issues.append(
            _issue(
                "SAG_LOCAL_ROUTING",
                "Local routing mode is invalid",
                "Set SAG_LOCAL_ROUTING to off, detected, or all.",
            )
        )

    environment = env.get("SAG_ENVIRONMENT", "development").strip().lower()
    if environment not in {"", "development", "dev", "production", "prod", "test", "testing"}:
        issues.append(
            _issue(
                "SAG_ENVIRONMENT",
                "Environment name is invalid",
                "Set SAG_ENVIRONMENT to development or production.",
            )
        )
    production = environment in {"production", "prod"}

    level = env.get("SAG_LOG_LEVEL", "INFO").upper()
    if level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        issues.append(
            _issue(
                "SAG_LOG_LEVEL",
                "Log level is invalid",
                "Set SAG_LOG_LEVEL to DEBUG, INFO, WARNING, ERROR, or CRITICAL.",
            )
        )

    for item in filter(
        None, (part.strip() for part in env.get("SAG_CUSTOM_PATTERNS", "").split(";"))
    ):
        entity, separator, pattern = item.partition("=")
        if not separator or not entity.strip() or not pattern.strip():
            issues.append(
                _issue(
                    "SAG_CUSTOM_PATTERNS",
                    "Custom pattern entry is malformed",
                    "Use ENTITY=regex for each SAG_CUSTOM_PATTERNS entry.",
                )
            )
            break

    for name in ("SAG_TOKEN_KEY", "SAG_VAULT_KEY"):
        raw = env.get(name, "")
        if (
            not raw
            and name == "SAG_VAULT_KEY"
            and any(_VERSIONED.fullmatch(key) and value for key, value in env.items())
        ):
            continue
        if not raw:
            status = "fail" if production else "warn"
            issues.append(
                ConfigIssue(
                    f"secrets.{name.lower()[4:]}",
                    status,
                    f"{name} is unset",
                    f"Set {name} to a persistent secret of at least "
                    f"{MIN_ROOT_SECRET_BYTES} decoded bytes.",
                    production,
                )
            )
        elif decoded_secret_length(raw) < MIN_ROOT_SECRET_BYTES:
            issues.append(
                _issue(
                    name,
                    f"{name} is too short",
                    f"Set {name} to at least {MIN_ROOT_SECRET_BYTES} decoded bytes.",
                    check_id=f"secrets.{name.lower()[4:]}.length",
                )
            )

    versions: set[int] = set()
    for name, raw in sorted(env.items()):
        match = _VERSIONED.fullmatch(name)
        if match and raw:
            version = int(match.group(1))
            if version in versions:
                issues.append(
                    _issue(
                        "SAG_VAULT_KEY",
                        "Vault key versions collide",
                        "Use one setting for each vault key version.",
                        check_id="secrets.vault_key.version_collision",
                    )
                )
            versions.add(version)
            if decoded_secret_length(raw) < MIN_ROOT_SECRET_BYTES:
                issues.append(
                    _issue(
                        name,
                        f"{name} is too short",
                        f"Set {name} to at least {MIN_ROOT_SECRET_BYTES} decoded bytes.",
                    )
                )
    if env.get("SAG_VAULT_KEY") and 1 in versions:
        issues.append(
            _issue(
                "SAG_VAULT_KEY",
                "Vault key version 1 is configured twice",
                "Use either SAG_VAULT_KEY or SAG_VAULT_KEY_V1.",
                check_id="secrets.vault_key.version_1_duplicate",
            )
        )
    if env.get("SAG_VAULT_KEY"):
        versions.add(1)
    active = env.get("SAG_VAULT_ACTIVE_KEY_VERSION", "")
    if active:
        try:
            selected = int(active)
        except ValueError:
            selected = -1
        if selected not in versions:
            issues.append(
                _issue(
                    "SAG_VAULT_ACTIVE_KEY_VERSION",
                    "Active vault key is unavailable",
                    "Set SAG_VAULT_ACTIVE_KEY_VERSION to a configured key version.",
                    check_id="secrets.vault_key.active",
                )
            )

    seen: set[str] = set()
    valid_keys = 0
    for item in filter(None, (part.strip() for part in env.get("SAG_API_KEYS", "").split(","))):
        parts = item.split(":")
        if len(parts) not in {2, 3} or any(not part for part in parts):
            issues.append(
                _issue(
                    "SAG_API_KEYS",
                    "API key entry is malformed",
                    "Use key:tenant[:application] for each SAG_API_KEYS entry.",
                    check_id="auth.api_keys.malformed",
                )
            )
            continue
        key = parts[0]
        if production and (not key.startswith(KEY_PREFIX) or len(key) < len(KEY_PREFIX) + 32):
            issues.append(
                _issue(
                    "SAG_API_KEYS",
                    "Production API key is too weak",
                    "Use a key with the sgw_live_ prefix and 32 random characters.",
                    check_id="auth.api_keys.weak",
                )
            )
            continue
        if key in seen:
            issues.append(
                _issue(
                    "SAG_API_KEYS",
                    "API key is duplicated",
                    "Use a different API key for each entry.",
                    check_id="auth.api_keys.duplicate",
                )
            )
            continue
        seen.add(key)
        valid_keys += 1
    if not valid_keys:
        issues.append(
            ConfigIssue(
                "auth.api_keys",
                "fail",
                "No usable API keys are configured",
                "Set SAG_API_KEYS so clients can authenticate.",
                production,
            )
        )

    return ParsedEnvironment(
        MappingProxyType(numbers), MappingProxyType(flags), routing, tuple(issues)
    )
